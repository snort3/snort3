//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

/*
 * stream_tcp.c authors:
 *     Martin Roesch <roesch@sourcefire.com>
 *     Steven Sturges <ssturges@sourcefire.com>
 *     Russ Combs <rcombs@sourcefire.com>
 */

/*
 * FIXITs:
 * - midstream ssn pickup (done, SAS 10/14/2005)
 * - syn flood protection (done, SAS 9/27/2005)
 *
 * - review policy anomaly detection
 *   + URG pointer (TODO)
 *   + data on SYN (done, SAS 10/12/2005)
 *   + data on FIN (done, SAS 10/12/2005)
 *   + data after FIN (done, SAS 10/13/2005)
 *   + window scaling/window size max (done, SAS 10/13/2005)
 *   + PAWS, TCP Timestamps (done, SAS 10/12/2005)
 *
 * - session shutdown/Reset handling (done, SAS)
 * - flush policy for Window/Consumed
 * - limit on number of overlapping packets (done, SAS)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <assert.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "main/analyzer.h"
#include "detection/detect.h"
#include "detection/detection_util.h"
#include "hash/sfxhash.h"
#include "utils/util.h"
#include "utils/sflsq.h"
#include "utils/snort_bounds.h"
#include "time/packet_time.h"
#include "perf_monitor/flow_ip_tracker.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "protocols/tcp_options.h"
#include "protocols/tcp.h"
#include "protocols/eth.h"
#include "log/log_text.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "flow/flow_control.h"
#include "flow/session.h"
#include "flow/memcap.h"
#include "profiler/profiler.h"
#include "file_api/file_api.h"
#include "sfip/sf_ip.h"
#include "normalize/normalize.h"
#include "perf_monitor/flow_tracker.h"
#include "filters/sfrf.h"

#include "stream/paf.h"
#include "stream_tcp.h"
#include "tcp_module.h"
#include "tcp_event_logger.h"
#include "tcp_debug_trace.h"

#include "tcp_state_none.h"
#include "tcp_state_closed.h"
#include "tcp_state_listen.h"
#include "tcp_state_syn_sent.h"
#include "tcp_state_syn_recv.h"
#include "tcp_state_established.h"
#include "tcp_state_close_wait.h"
#include "tcp_state_closing.h"
#include "tcp_state_fin_wait1.h"
#include "tcp_state_fin_wait2.h"
#include "tcp_state_last_ack.h"
#include "tcp_state_time_wait.h"

#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"
#include "tcp_session.h"

#ifdef DEBUG
const char* const flush_policy_names[] =
{
    "ignore",
    "on-ack",
    "on-data"
};
#endif

void TcpSession::update_perf_base_state(char newState)
{
    uint32_t session_flags = flow->get_session_flags();
    switch ( newState )
    {
    case TcpStreamTracker::TCP_SYN_SENT:
        if ( !( session_flags & SSNFLAG_COUNTED_INITIALIZE ) )
        {
            tcpStats.sessions_initializing++;
            session_flags |= SSNFLAG_COUNTED_INITIALIZE;
        }
        break;

    case TcpStreamTracker::TCP_ESTABLISHED:
        if ( !( session_flags & SSNFLAG_COUNTED_ESTABLISH ) )
        {
            tcpStats.sessions_established++;
            if ( perfmon_config && ( perfmon_config->perf_flags & SFPERF_FLOWIP ) )
                perf_flow_ip->updateState(&flow->client_ip,
                    &flow->server_ip, SFS_STATE_TCP_ESTABLISHED);

            session_flags |= SSNFLAG_COUNTED_ESTABLISH;
            if ( ( session_flags & SSNFLAG_COUNTED_INITIALIZE )
                && !( session_flags & SSNFLAG_COUNTED_CLOSING ) )
            {
                assert(tcpStats.sessions_initializing);
                tcpStats.sessions_initializing--;
            }
        }
        break;

    case TcpStreamTracker::TCP_CLOSING:
        if ( !( session_flags & SSNFLAG_COUNTED_CLOSING ) )
        {
            tcpStats.sessions_closing++;
            session_flags |= SSNFLAG_COUNTED_CLOSING;

            if ( session_flags & SSNFLAG_COUNTED_ESTABLISH )
            {
                assert(tcpStats.sessions_established);
                tcpStats.sessions_established--;

                if (perfmon_config  && (perfmon_config->perf_flags & SFPERF_FLOWIP))
                    perf_flow_ip->updateState(&flow->client_ip, &flow->server_ip,
                        SFS_STATE_TCP_CLOSED);
            }
            else if ( session_flags & SSNFLAG_COUNTED_INITIALIZE )
            {
                assert(tcpStats.sessions_initializing);
                tcpStats.sessions_initializing--;
            }
        }
        break;

    case TcpStreamTracker::TCP_CLOSED:
        if ( session_flags & SSNFLAG_COUNTED_CLOSING )
        {
            assert(tcpStats.sessions_closing);
            tcpStats.sessions_closing--;
        }
        else if ( session_flags & SSNFLAG_COUNTED_ESTABLISH )
        {
            assert(tcpStats.sessions_established);
            tcpStats.sessions_established--;

            if ( perfmon_config && ( perfmon_config->perf_flags & SFPERF_FLOWIP ) )
                perf_flow_ip->updateState(&flow->client_ip,
                    &flow->server_ip, SFS_STATE_TCP_CLOSED);
        }
        else if ( session_flags & SSNFLAG_COUNTED_INITIALIZE )
        {
            assert(tcpStats.sessions_initializing);
            tcpStats.sessions_initializing--;
        }
        break;

    default:
        break;
    }

    flow->update_session_flags(session_flags);
    tcpStats.mem_in_use = tcp_memcap->used();
}

//-------------------------------------------------------------------------
// when client ports are configured, that means c2s and is stored on the
// client side; when the session starts, the server policy is obtained from
// the client side because segments are stored on the receiving side.
//
// this could be improved further by storing the c2s policy on the server
// side and then obtaining server policy from the server on session
// startup.
//
// either way, this client / server distinction must be kept in mind to
// make sense of the code in this file.
//-------------------------------------------------------------------------

#ifdef DEBUG_STREAM_EX
// FIXIT - FlushMgr is no longer defined - confirm this and delete or refactor to use
// what replaced FlushMgr
static void PrintFlushMgr(FlushMgr* fm)
{
    if (fm == NULL)
        return;

    switch (fm->flush_policy)
    {
    case STREAM_FLPOLICY_IGNORE:
        DebugMessage(DEBUG_STREAM_STATE, "    IGNORE\n");
        break;

    case STREAM_FLPOLICY_ON_ACK:
        DebugMessage(DEBUG_STREAM_STATE, "    PROTOCOL\n");
        break;

    case STREAM_FLPOLICY_ON_DATA:
        DebugMessage(DEBUG_STREAM_STATE, "    PROTOCOL_IPS\n");
        break;
    }
}

#endif  // DEBUG_STREAM_EX

static inline int is_mac_address_valid(TcpTracker* talker, TcpTracker* listener, Packet* p)
{
    int event_code = 0;
    bool t_hijack = true, l_hijack = true;

    if (!(p->proto_bits & PROTO_BIT__ETH))
        return 0;

    // if flag is set, gauranteed to have an eth layer
    const eth::EtherHdr* eh = layer::get_eth_layer(p);

    if ( talker->compare_mac_addresses(eh->ether_src) )
    {
        t_hijack = false;
        if ( listener->compare_mac_addresses(eh->ether_dst) )
            l_hijack = false;
    }
    else if ( listener->compare_mac_addresses(eh->ether_dst) )
        l_hijack = false;

    if ( t_hijack & l_hijack )
    {
        if ( talker->compare_mac_addresses(eh->ether_dst) &&
            listener->compare_mac_addresses(eh->ether_src) )
            // this is probably a tap
            return event_code;
    }

    if ( t_hijack )
    {
        if ( p->packet_flags & PKT_FROM_CLIENT )
            event_code |= EVENT_SESSION_HIJACK_CLIENT;
        else
            event_code |= EVENT_SESSION_HIJACK_SERVER;
    }

    if ( l_hijack )
    {
        if ( p->packet_flags & PKT_FROM_CLIENT )
            event_code |= EVENT_SESSION_HIJACK_SERVER;
        else
            event_code |= EVENT_SESSION_HIJACK_CLIENT;
    }

    return event_code;
}

#ifdef S5_PEDANTIC
// From RFC 793:
//
//    Segment Receive  Test
//    Length  Window
//    ------- -------  -------------------------------------------
//
//       0       0     SEG.SEQ = RCV.NXT
//
//       0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//
//      >0       0     not acceptable
//
//      >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//                     or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
//
static inline int ValidSeq(const Packet* p, Flow* flow, TcpTracker* st, TcpSegmentDescriptor& tsd)
{
    uint32_t win = st->normalizer->get_stream_window(flow, st, tsd);

    if ( !p->dsize )
    {
        if ( !win )
        {
            return ( tsd.get_seq() == st->r_win_base );
        }
        return SEQ_LEQ(st->r_win_base, tsd.get_seq()) &&
               SEQ_LT(tsd.get_seq(), st->r_win_base+win);
    }
    if ( !win )
        return 0;

    if ( SEQ_LEQ(st->r_win_base, tsd.get_seq()) &&
        SEQ_LT(tsd.get_seq(), st->r_win_base+win) )
        return 1;

    return SEQ_LEQ(st->r_win_base, tsd.get_end_seq()) &&
           SEQ_LT(tsd.get_end_seq(), st->r_win_base+win);
}

#else
static inline int ValidSeq(TcpTracker* st, TcpSegmentDescriptor& tsd)
{
    int right_ok;
    uint32_t left_seq;

    DebugFormat(DEBUG_STREAM_STATE,
        "Checking end_seq (%X) > r_win_base (%X) && seq (%X) < r_nxt_ack(%X)\n",
        tsd.get_end_seq(), st->r_win_base, tsd.get_seq(), st->r_nxt_ack +
        st->normalizer->get_stream_window(tsd));

    if ( SEQ_LT(st->r_nxt_ack, st->r_win_base) )
        left_seq = st->r_nxt_ack;
    else
        left_seq = st->r_win_base;

    if ( tsd.get_pkt()->dsize )
        right_ok = SEQ_GT(tsd.get_end_seq(), left_seq);
    else
        right_ok = SEQ_GEQ(tsd.get_end_seq(), left_seq);

    if ( right_ok )
    {
        uint32_t win = st->normalizer->get_stream_window(tsd);

        if ( SEQ_LEQ(tsd.get_seq(), st->r_win_base + win) )
        {
            DebugMessage(DEBUG_STREAM_STATE, "seq is within window!\n");
            return 1;
        }
        else
        {
            DebugMessage(DEBUG_STREAM_STATE, "seq is past the end of the window!\n");
        }
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "end_seq is before win_base\n");
    }
    return 0;
}

#endif

static inline void UpdateSsn(TcpTracker* rcv, TcpTracker* snd, TcpSegmentDescriptor& tsd)
{
#if 0
    // FIXIT-L these checks are a hack to avoid off by one normalization
    // due to FIN ... if last segment filled a hole, r_nxt_ack is not at
    // end of data, FIN is ignored so sequence isn't bumped, and this
    // forces seq-- on ACK of FIN.  :(
    if ( rcv->get_tcp_state() == TcpStreamTracker::TCP_ESTABLISHED &&
        rcv->s_mgr.state_queue == TcpStreamTracker::TCP_STATE_NONE &&
        Normalize_IsEnabled(NORM_TCP_IPS) )
    {
        // walk the seglist until a gap or tsd.ack whichever is first
        // if a gap exists prior to ack, move ack back to start of gap
        TcpSegment* seg = snd->seglist;

        // FIXIT-L must check ack oob with empty seglist
        // FIXIT-L add lower gap bound to tracker for efficiency?
        while ( seg )
        {
            uint32_t seq = seg->seq + seg->size;
            if ( SEQ_LEQ(tsd.get_ack(), seq) )
                break;

            seg = seg->next;

            if ( !seg || seg->seq > seq )
            {
                // normalize here
                tsd.set_ack(seq);
                tcph->th_ack = htonl(seq);
                p->packet_flags |= PKT_MODIFIED;
                break;
            }
        }
    }
#endif
    // ** if we don't see a segment, we can't track seq at ** below
    // so we update the seq by the ack if it is beyond next expected
    if ( SEQ_GT(tsd.get_ack(), rcv->get_snd_una() ) )
        rcv->set_snd_una(tsd.get_ack() );

    // ** this is how we track the last seq number sent
    // as is l_unackd is the "last left" seq recvd
    snd->set_snd_una(tsd.get_seq() );

    if ( SEQ_GT(tsd.get_end_seq(), snd->get_snd_nxt() ) )
        snd->set_snd_nxt(tsd.get_end_seq() );

    if ( !SEQ_EQ(snd->r_win_base, tsd.get_ack() ) )
    {
        snd->small_seg_count = 0;
    }
#ifdef S5_PEDANTIC
    if ( SEQ_GT(tsd.get_ack(), snd->r_win_base) &&
        SEQ_LEQ(tsd.get_ack(), snd->r_nxt_ack) )
#else
    if ( SEQ_GT(tsd.get_ack(), snd->r_win_base) )
#endif
        snd->r_win_base = tsd.get_ack();

    snd->set_snd_wnd(tsd.get_win() );
}

void TcpSession::clear_session(int freeApplicationData)
{
    // update stats
    if ( tcp_init )
        tcpStats.released++;
    else if ( lws_init )
        tcpStats.no_pickups++;
    else
        return;

    update_perf_base_state(TcpStreamTracker::TCP_CLOSED);

    if (flow->get_session_flags() & SSNFLAG_PRUNED)
        tcpStats.prunes++;
    else if (flow->get_session_flags() & SSNFLAG_TIMEDOUT)
        tcpStats.timeouts++;
    tcpStats.released++;

    set_splitter(true, nullptr);
    set_splitter(false, nullptr);

    DebugFormat(DEBUG_STREAM_STATE, "In TcpSessionClear, %lu bytes in use\n", tcp_memcap->used());

    if ( client->reassembler )
    {
        DebugFormat(DEBUG_STREAM_STATE, "client has %d segs queued, freeing all.\n",
            client->reassembler->get_seg_count());
        client->reassembler->purge_segment_list();
    }

    if ( server->reassembler )
    {
        DebugFormat(DEBUG_STREAM_STATE, "server has %d segs queued, freeing all\n",
            server->reassembler->get_seg_count());
        server->reassembler->purge_segment_list();
    }

    paf_clear(&client->paf_state);
    paf_clear(&server->paf_state);

    // update light-weight state
    if ( freeApplicationData == 2 )
        flow->restart(true);
    else
        flow->clear(freeApplicationData);

    // generate event for rate filtering
    tel->EventInternal(INTERNAL_EVENT_SESSION_DEL);

    DebugFormat(DEBUG_STREAM_STATE, "After cleaning, %lu bytes in use\n", tcp_memcap->used());

    lws_init = tcp_init = false;
}

void TcpSession::cleanup_session(int freeApplicationData, Packet* p)
{
    // FIXIT - this function does both client & server sides...refactor to do one and
    // call for each
    if ( client->reassembler != nullptr )
        client->reassembler->flush_queued_segments(flow, true, p);
    if ( server->reassembler != nullptr )
        server->reassembler->flush_queued_segments(flow, true, p);

    clear_session(freeApplicationData);
}

#if 0
static inline int IsWellFormed(Packet* p, TcpTracker* ts)
{
    return ( !ts->mss || (p->dsize <= ts->mss) );
}

#endif

void TcpSession::FinishServerInit(TcpSegmentDescriptor& tsd)
{
    const tcp::TCPHdr* tcph = tsd.get_tcph();

    server->set_snd_wnd(tsd.get_win() );
    server->set_snd_una(tsd.get_seq() + 1);
    server->set_snd_nxt(server->get_snd_una() );
    server->set_iss(tsd.get_seq() );

    client->r_nxt_ack = tsd.get_end_seq();

    if ( tcph->is_fin() )
        server->set_snd_nxt(server->get_snd_nxt() - 1);

    if ( !( flow->session_state & STREAM_STATE_MIDSTREAM ) )
    {
        server->set_tcp_state(TcpStreamTracker::TCP_SYN_RECV);
        client->reassembler->set_seglist_base_seq(server->get_snd_una() );
        client->r_win_base = tsd.get_end_seq();
    }
    else
    {
        client->reassembler->set_seglist_base_seq(tsd.get_seq() );
        client->r_win_base = tsd.get_seq();
    }

    server->flags |= server->normalizer->get_tcp_timestamp(tsd, false);
    server->ts_last = tsd.get_ts();
    if (server->ts_last == 0)
        server->flags |= TF_TSTAMP_ZERO;
    else
        server->set_ts_last_packet(tsd.get_pkt()->pkth->ts.tv_sec);

    server->flags |= tsd.init_mss(&server->mss);
    server->flags |= tsd.init_wscale(&server->wscale);

#ifdef DEBUG_STREAM_EX
    PrintTcpSession(ssn);
#endif
}

void TcpSession::EndOfFileHandle(Packet* p)
{
    flow->call_handlers(p, true);
}

bool TcpSession::flow_exceeds_config_thresholds(TcpTracker* rcv, TcpSegmentDescriptor& tsd)
{
    if (rcv->flush_policy == STREAM_FLPOLICY_IGNORE)
    {
        DebugMessage(DEBUG_STREAM_STATE, "Ignoring segment due to IGNORE flush_policy\n");
        return true;
    }

    if ( ( config->flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY ) && !flow->two_way_traffic() )
        return true;

    if ( config->max_consec_small_segs && ( tsd.get_pkt()->dsize <
        config->max_consec_small_seg_size ) )
    {
        rcv->small_seg_count++;

        if ( rcv->small_seg_count > config->max_consec_small_segs )
        {
            /* Above threshold, log it...  in this TCP policy,
             * action controlled by preprocessor rule. */
            tel->EventMaxSmallSegsExceeded();
            /* Reset counter, so we're not too noisy */
            rcv->small_seg_count = 0;
        }
    }

    if ( config->max_queued_bytes
        && ( rcv->reassembler->get_seg_bytes_total() > config->max_queued_bytes ) )
    {
        tcpStats.max_bytes++;
        return true;
    }

    if ( config->max_queued_segs
        && ( rcv->reassembler->get_seg_count() + 1 > config->max_queued_segs ) )
    {
        tcpStats.max_segs++;
        return true;
    }

    return false;
}

void TcpSession::process_tcp_stream(TcpTracker* rcv, TcpSegmentDescriptor& tsd)
{
    DebugFormat(DEBUG_STREAM_STATE, "In ProcessTcpStream(), %d bytes to queue\n",
        tsd.get_pkt()->dsize);

    if (tsd.get_pkt()->packet_flags & PKT_IGNORE)
        return;

    SetPacketHeaderFoo(tsd.get_pkt() );

    if ( flow_exceeds_config_thresholds(rcv, tsd) )
        return;

    DebugMessage(DEBUG_STREAM_STATE, "queuing segment\n");
    rcv->reassembler->queue_packet_for_reassembly(tsd);

    // Alert if overlap limit exceeded
    if ( ( config->overlap_limit )
        && ( rcv->reassembler->get_overlap_count() > config->overlap_limit ) )
    {
        tel->EventExcessiveOverlap();
        rcv->reassembler->set_overlap_count(0);
    }
}

int TcpSession::process_tcp_data(TcpTracker* listener, TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpDataPerfStats);

    const tcp::TCPHdr* tcph = tsd.get_tcph();
    uint32_t seq = tsd.get_seq();

    if ( tcph->is_syn() )
    {
        if (listener->normalizer->get_os_policy() == StreamPolicy::OS_MACOS)
            seq++;

        else
        {
            DebugMessage(DEBUG_STREAM_STATE, "Bailing, data on SYN, not MAC Policy!\n");
            listener->normalizer->trim_syn_payload(tsd);
            return STREAM_UNALIGNED;
        }
    }

    /* we're aligned, so that's nice anyway */
    if (seq == listener->r_nxt_ack)
    {
        /* check if we're in the window */
        if (config->policy != StreamPolicy::OS_PROXY
            and listener->normalizer->get_stream_window(tsd) == 0)
        {
            DebugMessage(DEBUG_STREAM_STATE, "Bailing, we're out of the window!\n");
            listener->normalizer->trim_win_payload(tsd);
            return STREAM_UNALIGNED;
        }

        /* move the ack boundry up, this is the only way we'll accept data */
        // FIXIT-L for ips, must move all the way to first hole or right end
        if ( listener->s_mgr.state_queue == TcpStreamTracker::TCP_STATE_NONE )
            listener->r_nxt_ack = tsd.get_end_seq();

        if (tsd.get_pkt()->dsize != 0)
        {
            if (!( flow->get_session_flags() & SSNFLAG_STREAM_ORDER_BAD))
                tsd.get_pkt()->packet_flags |= PKT_STREAM_ORDER_OK;

            process_tcp_stream(listener, tsd);
            /* set flags to session flags */

            return STREAM_ALIGNED;
        }
    }
    else
    {
        // pkt is out of order, do some target-based shizzle here...
        // NO, we don't want to simply bail.  Some platforms favor unack'd dup data over the
        // original data.  Let the reassembly policy decide how to handle the overlapping data.
        // See HP, Solaris, et al. for those that favor duplicate data over the original in
        // some cases.
        DebugFormat(DEBUG_STREAM_STATE,
            "out of order segment (tsd.seq: 0x%X l->r_nxt_ack: 0x%X!\n",
            tsd.get_seq(), listener->r_nxt_ack);

        if (listener->s_mgr.state_queue == TcpStreamTracker::TCP_STATE_NONE)
        {
            /* check if we're in the window */
            if (config->policy != StreamPolicy::OS_PROXY
                and listener->normalizer->get_stream_window(tsd) == 0)
            {
                DebugMessage(DEBUG_STREAM_STATE, "Bailing, we're out of the window!\n");
                listener->normalizer->trim_win_payload(tsd);
                return STREAM_UNALIGNED;
            }

            if ((listener->get_tcp_state() == TcpStreamTracker::TCP_ESTABLISHED)
                && (listener->flush_policy == STREAM_FLPOLICY_IGNORE))
            {
                if (SEQ_GT(tsd.get_end_seq(), listener->r_nxt_ack))
                {
                    // set next ack so we are within the window going forward on this side.
                    // FIXIT-L for ips, must move all the way to first hole or right end
                    listener->r_nxt_ack = tsd.get_end_seq();
                }
            }
        }

        if (tsd.get_pkt()->dsize != 0)
        {
            if (!( flow->get_session_flags() & SSNFLAG_STREAM_ORDER_BAD))
            {
                if (!SEQ_LEQ((tsd.get_seq() + tsd.get_pkt()->dsize), listener->r_nxt_ack))
                    flow->set_session_flags(SSNFLAG_STREAM_ORDER_BAD);
            }
            process_tcp_stream(listener, tsd);
        }
    }

    return STREAM_UNALIGNED;
}

void TcpSession::set_os_policy(void)
{
    StreamPolicy client_os_policy = flow->ssn_policy ?
        static_cast<StreamPolicy>( flow->ssn_policy ) : config->policy;
    StreamPolicy server_os_policy = flow->ssn_policy ?
        static_cast<StreamPolicy>( flow->ssn_policy ) : config->policy;

    if ( client->normalizer == nullptr )
        client->normalizer = TcpNormalizerFactory::create(this, client_os_policy, client, server);

    if ( server->normalizer == nullptr )
        server->normalizer = TcpNormalizerFactory::create(this, server_os_policy, server, client);

    if ( client->reassembler == nullptr )
        client->reassembler = TcpReassemblerFactory::create(this, client, client_os_policy, false);

    if ( server->reassembler == nullptr )
        server->reassembler = TcpReassemblerFactory::create(this, server, server_os_policy, true);
}

// FIXIT - check for need to swap client/server is ifdef'ed out...
void TcpSession::swap_trackers(void)
{
    uint32_t session_flags = flow->get_session_flags( );
    if ( ( session_flags & SSNFLAG_CLIENT_SWAP ) && !( session_flags & SSNFLAG_CLIENT_SWAPPED ) )
    {
        TcpTracker* trk = client;
        client = server;
        server = trk;

        sfip_t ip = flow->client_ip;
        flow->client_ip = flow->server_ip;
        flow->server_ip = ip;

        uint16_t port = flow->client_port;
        flow->client_port = flow->server_port;
        flow->server_port = port;

        if ( !flow->two_way_traffic() )
        {
            if ( session_flags & SSNFLAG_SEEN_CLIENT )
            {
                session_flags ^= SSNFLAG_SEEN_CLIENT;
                session_flags |= SSNFLAG_SEEN_SERVER;
            }
            else if ( session_flags & SSNFLAG_SEEN_SERVER )
            {
                session_flags ^= SSNFLAG_SEEN_SERVER;
                session_flags |= SSNFLAG_SEEN_CLIENT;
            }
        }

        session_flags |= SSNFLAG_CLIENT_SWAPPED;
        flow->update_session_flags(session_flags);
    }
}

void TcpSession::init_new_tcp_session(TcpSegmentDescriptor& tsd)
{
    flow->protocol = tsd.get_pkt()->type();

    /* New session, previous was marked as reset.  Clear the reset flag. */
    flow->clear_session_flags(SSNFLAG_RESET);
    flow->set_expire(tsd.get_pkt(), config->session_timeout);

    update_perf_base_state(TcpStreamTracker::TCP_SYN_SENT);
    tel->EventInternal(INTERNAL_EVENT_SESSION_ADD);

    //assert( !tcp_init );
    tcp_init = true;
    new_ssn = true;

    // FIXIT - this state is bogus... move to tracker init...
    tcpStats.created++;
}

void TcpSession::NewTcpSessionOnSyn(TcpSegmentDescriptor& tsd)
{
    server->init_on_syn_recv(tsd);
    client->init_on_syn_sent(tsd);
    init_new_tcp_session(tsd);
    tcpStats.sessions_on_syn++;
}

void TcpSession::NewTcpSessionOnSynAck(TcpSegmentDescriptor& tsd)
{
    server->init_on_synack_sent(tsd);
    client->init_on_synack_recv(tsd);
    init_new_tcp_session(tsd);
    tcpStats.sessions_on_syn_ack++;
}

void TcpSession::update_session_state(const tcp::TCPHdr* tcph, TcpSegmentDescriptor& tsd)
{
    /* If session is already marked as established */
    if (!(flow->session_state & STREAM_STATE_ESTABLISHED)
        && (!require_3whs || config->midstream_allowed(tsd.get_pkt())))
    {
        /* If not requiring 3-way Handshake...
           TCP session created on TH_SYN above, or maybe on SYN-ACK, or anything else
           Need to update Lightweight session state */
        if (tcph->is_syn_ack())
        {
            /* SYN-ACK from server */
            if (flow->session_state != STREAM_STATE_NONE)
            {
                flow->session_state |= STREAM_STATE_SYN_ACK;
                update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
            }
        }
        else if (tcph->is_ack() && (flow->session_state & STREAM_STATE_SYN_ACK))
        {
            flow->session_state |= STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED;
            update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }
}

void TcpSession::update_session_on_server_packet(const tcp::TCPHdr* tcph,
    TcpSegmentDescriptor& tsd)
{
    DebugMessage(DEBUG_STREAM_STATE, "Stream: Updating on packet from server\n");

    flow->set_session_flags(SSNFLAG_SEEN_SERVER);
    if (tcp_init)
    {
        talker = server;
        listener = client;
    }

    if (talker && (talker->get_tcp_state() == TcpStreamTracker::TCP_LISTEN) && tcph->is_syn_only())
        tel->set_tcp_event(EVENT_4WHS);

    /* If we picked this guy up midstream, finish the initialization */
    if ((flow->session_state & STREAM_STATE_MIDSTREAM) && !(flow->session_state &
        STREAM_STATE_ESTABLISHED))
    {
        FinishServerInit(tsd);
        if (tcph->are_flags_set(TH_ECE) && (flow->get_session_flags() & SSNFLAG_ECN_CLIENT_QUERY))
            flow->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

        if (flow->get_session_flags() & SSNFLAG_SEEN_CLIENT)
        {
            // should TCP state go to established too?
            flow->session_state |= STREAM_STATE_ESTABLISHED;
            flow->set_session_flags(SSNFLAG_ESTABLISHED);
            update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }

    if (!flow->inner_server_ttl)
        flow->set_ttl(tsd.get_pkt(), false);
}

void TcpSession::update_session_on_client_packet(TcpSegmentDescriptor& tsd)
{
    DebugMessage(DEBUG_STREAM_STATE, "Stream: Updating on packet from client\n");

    /* if we got here we had to see the SYN already... */
    flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
    if (tcp_init)
    {
        talker = client;
        listener = server;
    }

    if ((flow->session_state & STREAM_STATE_MIDSTREAM)
        && !(flow->session_state & STREAM_STATE_ESTABLISHED))
    {
        /* Midstream and seen server. */
        if (flow->get_session_flags() & SSNFLAG_SEEN_SERVER)
        {
            flow->session_state |= STREAM_STATE_ESTABLISHED;
            flow->set_session_flags(SSNFLAG_ESTABLISHED);
        }
    }

    if (!flow->inner_client_ttl)
        flow->set_ttl(tsd.get_pkt(), true);
}

bool TcpSession::handle_syn_on_reset_session(const tcp::TCPHdr* tcph, TcpSegmentDescriptor& tsd)
{
    if ( !tcp_init || ( listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSED )
        || ( talker->get_tcp_state() == TcpStreamTracker::TCP_CLOSED ) )
    {
        /* Listener previously issued a reset Talker is re-SYN-ing */
        // FIXIT-L this leads to bogus 129:20
        cleanup_session(1);

        if ( tcph->is_rst() )
        {
            /* FIXIT-M  In inline mode, only one of the normalizations
             *           can occur.  If the first normalization
             *           fires, there is nothing for the second normalization
             *           to do.  However, in inline-test mode, since
             *           nothing is actually normalized, both of the
             *           following functions report that they 'would'
             *           normalize. i.e., both functions increment their
             *           count even though only one function can ever
             *           perform a normalization.
             */

            /* Got SYN/RST.  We're done. */
            listener->normalizer->trim_syn_payload(tsd);
            listener->normalizer->trim_rst_payload(tsd);
            pkt_action_mask |= ACTION_RST;
            return false;
        }
        else if (tcph->is_syn_only())
        {
            flow->ssn_state.direction = FROM_CLIENT;
            flow->session_state = STREAM_STATE_SYN;
            flow->set_ttl(tsd.get_pkt(), true);
            NewTcpSessionOnSyn(tsd);
            tcpStats.resyns++;
            listener = server;
            talker = client;
            listener->normalizer->ecn_tracker( (tcp::TCPHdr*)tcph, require_3whs);
            flow->update_session_flags(SSNFLAG_SEEN_CLIENT);
        }
        else if (tcph->is_syn_ack())
        {
            if (config->midstream_allowed(tsd.get_pkt()))
            {
                flow->ssn_state.direction = FROM_SERVER;
                flow->session_state = STREAM_STATE_SYN_ACK;
                flow->set_ttl(tsd.get_pkt(), false);
                NewTcpSessionOnSynAck(tsd);
                tcpStats.resyns++;
            }

            listener = client;
            talker = server;
            listener->normalizer->ecn_tracker( (tcp::TCPHdr*)tcph, require_3whs);
            flow->update_session_flags(SSNFLAG_SEEN_SERVER);
        }
    }

    DebugMessage(DEBUG_STREAM_STATE, "Got SYN pkt on reset ssn, re-SYN-ing\n");

    return true;
}

void TcpSession::update_ignored_session(TcpSegmentDescriptor& tsd)
{
    // FIXIT-L why flush here instead of just purge?
    // s5_ignored_session() may be disabling detection too soon if we really want to flush
    if (stream.ignored_session(flow, tsd.get_pkt()))
    {
        if (talker && (talker->flags & TF_FORCE_FLUSH))
        {
            flush_talker(tsd.get_pkt());
            talker->flags &= ~TF_FORCE_FLUSH;
        }
        if (listener && (listener->flags & TF_FORCE_FLUSH))
        {
            flush_listener(tsd.get_pkt());
            listener->flags &= ~TF_FORCE_FLUSH;
        }
        tsd.get_pkt()->packet_flags |= PKT_IGNORE;
        pkt_action_mask |= ACTION_DISABLE_INSPECTION;
    }
}

void TcpSession::handle_data_on_syn(const tcp::TCPHdr* tcph, TcpSegmentDescriptor& tsd)
{
    /* Handle data on SYN */
    if ((tsd.get_pkt()->dsize) && tcph->is_syn())
    {
        /* MacOS accepts data on SYN, so don't alert if policy is MACOS */
        if (talker->normalizer->get_os_policy() != StreamPolicy::OS_MACOS)
        {
            // remove data on SYN
            listener->normalizer->trim_syn_payload(tsd);

            if (Normalize_GetMode(NORM_TCP_TRIM_SYN) == NORM_MODE_OFF)
            {
                DebugMessage(DEBUG_STREAM_STATE, "Got data on SYN packet, not processing it\n");
                //EventDataOnSyn(config);
                tel->set_tcp_event(EVENT_DATA_ON_SYN);
                pkt_action_mask |= ACTION_BAD_PKT;
            }
        }
    }
}

void TcpSession::process_tcp_packet(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpStatePerfStats);

    int got_ts = 0;
    talker = nullptr;
    listener = nullptr;
    const tcp::TCPHdr* tcph = tsd.get_tcph();

    DEBUG_WRAP(const char* t = NULL; const char* l = NULL; );

    /* If session is already marked as established */
    update_session_state(tcph, tsd);

    if ( tcph->is_syn() )
        server->normalizer->ecn_tracker( (tcp::TCPHdr*)tcph, config->require_3whs() );

    if ( tsd.get_pkt()->packet_flags & PKT_FROM_SERVER )
    {
        update_session_on_server_packet(tcph, tsd);
        DEBUG_WRAP(t = "Server"; l = "Client");
    }
    else
    {
        update_session_on_client_packet(tsd);
        DEBUG_WRAP(t = "Server"; l = "Client");
    }

    //check for SYN on reset session
    if ( ( flow->get_session_flags() & SSNFLAG_RESET ) && tcph->is_syn() )
        if ( !handle_syn_on_reset_session(tcph, tsd) )
            return;

    update_ignored_session(tsd);

    handle_data_on_syn(tcph, tsd);

    if (!tcp_init)
        return;

    DebugFormat(DEBUG_STREAM_STATE, "   %s [talker] state: %s\n", t,
        tcp_state_names[talker->get_tcp_state()]);
    DebugFormat(DEBUG_STREAM_STATE, "   %s state: %s(%d)\n", l,
        tcp_state_names[listener->get_tcp_state()], listener->get_tcp_state());

    // may find better placement to eliminate redundant flag checks
    if ( tcph->is_syn() )
        talker->s_mgr.sub_state |= SUB_SYN_SENT;
    if ( tcph->is_ack() )
        talker->s_mgr.sub_state |= SUB_ACK_SENT;

    // process SYN ACK on unestablished sessions
    if ( ( TcpStreamTracker::TCP_SYN_SENT == listener->get_tcp_state() ) &&
        ( TcpStreamTracker::TCP_LISTEN == talker->get_tcp_state() ) )
    {
        if ( tcph->is_ack() )
        {
            // make sure we've got a valid segment
            if (!listener->is_ack_valid(tsd.get_ack() ) )
            {
                DebugFormat(DEBUG_STREAM_STATE,
                    "Pkt Ack is Out of Bounds (%X, %X, %X) = (snd_una, snd_nxt, cur)\n",
                    listener->get_snd_una(), listener->get_snd_nxt(), tsd.get_ack());
                inc_tcp_discards();
                listener->normalizer->trim_win_payload(tsd);
                pkt_action_mask |= ACTION_BAD_PKT;
                return;
            }
        }

        talker->flags |= talker->normalizer->get_tcp_timestamp(tsd, false);
        if (tsd.get_ts() == 0)
            talker->flags |= TF_TSTAMP_ZERO;

        // catch resets sent by server
        if ( tcph->is_rst() )
        {
            DebugMessage(DEBUG_STREAM_STATE, "got RST\n");

            listener->normalizer->trim_rst_payload(tsd);

            // Reset is valid when in SYN_SENT if the ack field ACKs the SYN.
            if ( listener->is_rst_valid_in_syn_sent(tsd) )
            {
                DebugMessage(DEBUG_STREAM_STATE, "got RST, closing talker\n");
                /* Reset is valid */
                /* Mark session as reset... Leave it around so that any
                 * additional data sent from one side or the other isn't
                 * processed (and is dropped in inline mode).
                 */
                flow->set_session_flags(SSNFLAG_RESET);
                talker->set_tcp_state(TcpStreamTracker::TCP_CLOSED);
                update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
                /* Leave listener open, data may be in transit */
                pkt_action_mask |= ACTION_RST;
                return;
            }
            /* Reset not valid. */
            DebugMessage(DEBUG_STREAM_STATE, "bad sequence number, bailing\n");
            inc_tcp_discards();
            tel->set_tcp_event(EVENT_BAD_RST);
            listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
            return;
        }

        // finish up server init
        if ( tcph->is_syn() )
        {
            FinishServerInit(tsd);
            if (talker->flags & TF_TSTAMP)
            {
                talker->set_ts_last_packet(tsd.get_pkt()->pkth->ts.tv_sec);
                talker->ts_last = tsd.get_ts();
            }

            DebugMessage(DEBUG_STREAM_STATE, "Finish server init got called!\n");
        }
        else
        {
            DebugMessage(DEBUG_STREAM_STATE, "Finish server init didn't get called!\n");
        }

        if ( tcph->are_flags_set(TH_ECE) && 
             ( flow->get_session_flags() & SSNFLAG_ECN_CLIENT_QUERY ) )
            flow->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

        // explicitly set the state
        listener->set_tcp_state(TcpStreamTracker::TCP_SYN_SENT);
        DebugMessage(DEBUG_STREAM_STATE, "Accepted SYN ACK\n");
        return;
    }

    /*
     * scale the window.  Only if BOTH client and server specified
     * wscale option as part of 3-way handshake.
     * This is per RFC 1323.
     */
    if ((talker->flags & TF_WSCALE) && (listener->flags & TF_WSCALE))
        tsd.set_win(tsd.get_win() << talker->wscale);

    /* Check for session hijacking -- compare mac address to the ones
     * that were recorded at session startup. */
#ifdef DAQ_PKT_FLAG_PRE_ROUTING
    if (!(tsd.get_pkt()->pkth->flags & DAQ_PKT_FLAG_PRE_ROUTING))
#endif
    {
        tel->set_tcp_event(is_mac_address_valid (talker, listener, tsd.get_pkt() ) );
    }

    pkt_action_mask |= listener->normalizer->handle_paws(tsd, &got_ts);

    // check RST validity
    if ( tcph->is_rst() )
    {
        listener->normalizer->trim_rst_payload(tsd);

        if (listener->normalizer->validate_rst(tsd))
        {
            DebugMessage(DEBUG_STREAM_STATE, "Got RST, bailing\n");

            if (listener->get_tcp_state() == TcpStreamTracker::TCP_FIN_WAIT1
                || listener->get_tcp_state() == TcpStreamTracker::TCP_FIN_WAIT2
                || listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSE_WAIT
                || listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSING)
            {
                flush_talker(tsd.get_pkt());
                flush_listener(tsd.get_pkt());
                set_splitter(true, nullptr);
                set_splitter(false, nullptr);
                flow->free_application_data();
            }

            flow->set_session_flags(SSNFLAG_RESET);
            talker->set_tcp_state(TcpStreamTracker::TCP_CLOSED);
            talker->s_mgr.sub_state |= SUB_RST_SENT;
            update_perf_base_state(TcpStreamTracker::TCP_CLOSING);

            if ( listener->normalizer->is_tcp_ips_enabled() )
                listener->set_tcp_state(TcpStreamTracker::TCP_CLOSED);

            /* else for ids: leave listener open, data may be in transit */
            pkt_action_mask |= ACTION_RST;
            return;
        }
        /* Reset not valid. */
        DebugMessage(DEBUG_STREAM_STATE, "bad sequence number, bailing\n");
        inc_tcp_discards();
        tel->set_tcp_event(EVENT_BAD_RST);
        listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
        return;
    }
    else
    {
        /* check for valid seqeuence/retrans */
        if (config->policy != StreamPolicy::OS_PROXY
            and (listener->get_tcp_state() >= TcpStreamTracker::TCP_ESTABLISHED)
            and !ValidSeq(listener, tsd))
        {
            DebugMessage(DEBUG_STREAM_STATE, "bad sequence number, bailing\n");
            inc_tcp_discards();
            listener->normalizer->trim_win_payload(tsd);
            return;
        }
    }

    if ( pkt_action_mask & ACTION_BAD_PKT )
    {
        DebugMessage(DEBUG_STREAM_STATE, "bad timestamp, bailing\n");
        inc_tcp_discards();
        return;
    }

    // update PAWS timestamps
    DebugFormat(DEBUG_STREAM_STATE, "PAWS update tsd.seq %lu > listener->r_win_base %lu\n",
        tsd.get_seq(), listener->r_win_base);
    if (got_ts && SEQ_EQ(listener->r_win_base, tsd.get_seq()))
    {
        if ( ( int32_t )( tsd.get_ts() - talker->ts_last ) >= 0 ||
            (uint32_t)tsd.get_pkt()->pkth->ts.tv_sec >= talker->get_ts_last_packet() + PAWS_24DAYS)
        {
            DebugMessage(DEBUG_STREAM_STATE, "updating timestamps...\n");
            talker->ts_last = tsd.get_ts();
            talker->set_ts_last_packet(tsd.get_pkt()->pkth->ts.tv_sec);
        }
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "not updating timestamps...\n");
    }

    // check for repeat SYNs
    if ( !new_ssn && tcph->is_syn_only() )
    {
        int action;
        if (!SEQ_EQ(tsd.get_seq(), talker->get_iss()) &&
             listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK))
            action = ACTION_BAD_PKT;
        else if (talker->get_tcp_state() >= TcpStreamTracker::TCP_ESTABLISHED)
            action = listener->normalizer->handle_repeated_syn(tsd);
        else
            action = ACTION_NOTHING;

        if (action != ACTION_NOTHING)
        {
            /* got a bad SYN on the session, alert! */
            tel->set_tcp_event(EVENT_SYN_ON_EST);
            pkt_action_mask |= action;
            return;
        }
    }

    // Check that the window is within the limits
    if (config->policy != StreamPolicy::OS_PROXY)
    {
        if (config->max_window && (tsd.get_win() > config->max_window))
        {
            DebugMessage(DEBUG_STREAM_STATE,
                "Got window that was beyond the allowed policy value, bailing\n");
            /* got a window too large, alert! */
            tel->set_tcp_event(EVENT_WINDOW_TOO_LARGE);
            inc_tcp_discards();
            listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
            pkt_action_mask |= ACTION_BAD_PKT;
            return;
        }
        else if ((tsd.get_pkt()->packet_flags & PKT_FROM_CLIENT) && (tsd.get_win() <= SLAM_MAX)
            && (tsd.get_ack() == listener->get_iss() + 1)
            && !( tcph->is_fin() | tcph->is_rst() )
            && !(flow->get_session_flags() & SSNFLAG_MIDSTREAM))
        {
            DebugMessage(DEBUG_STREAM_STATE, "Window slammed shut!\n");
            /* got a window slam alert! */
            tel->set_tcp_event(EVENT_WINDOW_SLAM);
            inc_tcp_discards();

            if (listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK))
            {
                pkt_action_mask |= ACTION_BAD_PKT;
                return;
            }
        }
    }

    if (talker->s_mgr.state_queue != TcpStreamTracker::TCP_STATE_NONE)
    {
        DebugFormat(DEBUG_STREAM_STATE,
            "Found queued state transition on ack 0x%X, current 0x%X!\n",
            talker->s_mgr.transition_seq, tsd.get_ack());

        if (tsd.get_ack() == talker->s_mgr.transition_seq)
        {
            DebugMessage(DEBUG_STREAM_STATE, "accepting transition!\n");
            talker->set_tcp_state(talker->s_mgr.state_queue);
            talker->s_mgr.state_queue = TcpStreamTracker::TCP_STATE_NONE;
        }
    }

    // process ACK flags
    if ( tcph->is_ack() )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Got an ACK...\n");
        DebugFormat(DEBUG_STREAM_STATE, " %s [listener] state: %s\n", l,
            tcp_state_names[listener->get_tcp_state()]);

        switch ( listener->get_tcp_state() )
        {
        case TcpStreamTracker::TCP_SYN_SENT:
            break;

        case TcpStreamTracker::TCP_SYN_RECV:
            DebugMessage(DEBUG_STREAM_STATE, "listener state is SYN_SENT...\n");
            if ( listener->is_ack_valid(tsd.get_ack() ) )
            {
                UpdateSsn(listener, talker, tsd);
                flow->set_session_flags(SSNFLAG_ESTABLISHED);
                flow->session_state |= STREAM_STATE_ESTABLISHED;
                listener->set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
                talker->set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
                update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
                /* Indicate this packet completes 3-way handshake */
                tsd.get_pkt()->packet_flags |= PKT_STREAM_TWH;
            }

            talker->flags |= got_ts;
            if (got_ts && SEQ_EQ(listener->r_nxt_ack, tsd.get_seq()))
            {
                talker->set_ts_last_packet(tsd.get_pkt()->pkth->ts.tv_sec);
                talker->ts_last = tsd.get_ts();
            }

            break;

        case TcpStreamTracker::TCP_ESTABLISHED:
        case TcpStreamTracker::TCP_CLOSE_WAIT:
            UpdateSsn(listener, talker, tsd);
            break;

        case TcpStreamTracker::TCP_FIN_WAIT1:
            UpdateSsn(listener, talker, tsd);

            DebugFormat(DEBUG_STREAM_STATE, "tsd.ack %X >= talker->r_nxt_ack %X\n", tsd.get_ack(),
                talker->r_nxt_ack);

            if ( SEQ_EQ(tsd.get_ack(), listener->get_snd_nxt() ) )
            {
                if ((listener->normalizer->get_os_policy() == StreamPolicy::OS_WINDOWS) &&
                    (tsd.get_win() == 0))
                {
                    tel->set_tcp_event(EVENT_WINDOW_SLAM);
                    inc_tcp_discards();

                    if (listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK))
                    {
                        pkt_action_mask |= ACTION_BAD_PKT;
                        return;
                    }
                }

                listener->set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT2);

                if ( tcph->is_fin() )
                {
                    DebugMessage(DEBUG_STREAM_STATE, "seq ok, setting state!\n");

                    if ( talker->s_mgr.state_queue == TcpStreamTracker::TCP_STATE_NONE )
                    {
                        talker->set_tcp_state(TcpStreamTracker::TCP_LAST_ACK);
                        EndOfFileHandle(tsd.get_pkt() );
                    }
                    if ( flow->get_session_flags() & SSNFLAG_MIDSTREAM )
                    {
                        // FIXIT-L this should be handled below in fin section
                        // but midstream sessions fail the seq test
                        listener->s_mgr.state_queue = TcpStreamTracker::TCP_TIME_WAIT;
                        listener->s_mgr.transition_seq = tsd.get_end_seq();
                        listener->s_mgr.expected_flags = TH_ACK;
                    }
                }
                else if ( listener->s_mgr.state_queue == TcpStreamTracker::TCP_CLOSING )
                {
                    listener->s_mgr.state_queue = TcpStreamTracker::TCP_TIME_WAIT;
                    listener->s_mgr.transition_seq = tsd.get_end_seq();
                    listener->s_mgr.expected_flags = TH_ACK;
                }
            }
            else
            {
                DebugMessage(DEBUG_STREAM_STATE, "bad ack!\n");
            }
            break;

        case TcpStreamTracker::TCP_FIN_WAIT2:
            UpdateSsn(listener, talker, tsd);
            if ( SEQ_GT(tsd.get_ack(), listener->get_snd_nxt() ) )
            {
                tel->set_tcp_event(EVENT_BAD_ACK);
                listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
                pkt_action_mask |= ACTION_BAD_PKT;
                return;
            }
            break;

        case TcpStreamTracker::TCP_CLOSING:
            UpdateSsn(listener, talker, tsd);
            if (SEQ_GEQ(tsd.get_end_seq(), listener->r_nxt_ack))
                listener->set_tcp_state(TcpStreamTracker::TCP_TIME_WAIT);
            break;

        case TcpStreamTracker::TCP_LAST_ACK:
            UpdateSsn(listener, talker, tsd);

            if ( SEQ_EQ(tsd.get_ack(), listener->get_snd_nxt() ) )
                listener->set_tcp_state(TcpStreamTracker::TCP_CLOSED);
            break;

        default:
            // FIXIT-L safe to ignore when inline?
            break;
        }

        talker->reassembler->flush_on_ack_policy(tsd.get_pkt() );
    }

    // handle data in the segment
    if (tsd.get_pkt()->dsize)
    {
        DebugFormat(DEBUG_STREAM_STATE, "   %s state: %s(%d) getting data\n",
            l, tcp_state_names[listener->get_tcp_state()], listener->get_tcp_state());

        // FIN means only that sender is done talking, other side may continue yapping.
        if ( TcpStreamTracker::TCP_FIN_WAIT2 == talker->get_tcp_state() ||
            TcpStreamTracker::TCP_TIME_WAIT == talker->get_tcp_state() )
        {
            // data on a segment when we're not accepting data any more alert!
            //EventDataOnClosed(talker->config);
            tel->set_tcp_event(EVENT_DATA_ON_CLOSED);
            pkt_action_mask |= ACTION_BAD_PKT;
            listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
        }
        else if ( TcpStreamTracker::TCP_CLOSED == talker->get_tcp_state() )
        {
            // data on a segment when we're not accepting data any more alert!
            if (flow->get_session_flags() & SSNFLAG_RESET)
            {
                //EventDataAfterReset(listener->config);
                if (talker->s_mgr.sub_state & SUB_RST_SENT)
                    tel->set_tcp_event(EVENT_DATA_AFTER_RESET);
                else
                    tel->set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
            }
            else
            {
                //EventDataOnClosed(listener->config);
                tel->set_tcp_event(EVENT_DATA_ON_CLOSED);
            }
            pkt_action_mask |= ACTION_BAD_PKT;
            listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
        }
        else
        {
            DebugFormat(DEBUG_STREAM_STATE, "Queuing data on listener, t %s, l %s...\n",
                flush_policy_names[talker->flush_policy],
                flush_policy_names[listener->flush_policy]);

            if (config->policy != StreamPolicy::OS_PROXY)
            {
                // these normalizations can't be done if we missed setup. and
                // window is zero in one direction until we've seen both sides.
                if (!(flow->get_session_flags() & SSNFLAG_MIDSTREAM) && flow->two_way_traffic())
                {
                    // sender of syn w/mss limits payloads from peer since we store mss on
                    // sender side, use listener mss same reasoning for window size
                    TcpTracker* st = listener;

                    // trim to fit in window and mss as needed
                    st->normalizer->trim_win_payload(tsd, ( st->r_win_base + st->get_snd_wnd() -
                        st->r_nxt_ack) );

                    if (st->mss)
                        st->normalizer->trim_mss_payload(tsd, st->mss);

                    st->normalizer->ecn_stripper(tsd.get_pkt() );
                }
            }
            // dunno if this is RFC but fragroute testing expects it  for the record,
            // I've seen FTP data sessions that send data packets with no tcp flags set
            if ((tcph->th_flags != 0)
                or (config->policy == StreamPolicy::OS_LINUX)
                or (config->policy == StreamPolicy::OS_PROXY))
            {
                process_tcp_data(listener, tsd);
            }
            else
            {
                tel->set_tcp_event(EVENT_DATA_WITHOUT_FLAGS);
                listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
            }
        }

        listener->reassembler->flush_on_data_policy(tsd.get_pkt() );
    }

    if ( tcph->is_fin() )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Got a FIN...\n");
        DebugFormat(DEBUG_STREAM_STATE,  "   %s state: %s(%d)\n", l,
            tcp_state_names[talker->get_tcp_state()], talker->get_tcp_state());
        DebugFormat(DEBUG_STREAM_STATE, "checking ack (0x%X) vs nxt_ack (0x%X)\n",
            tsd.get_end_seq(), listener->r_win_base);

        if ( SEQ_LT(tsd.get_end_seq(), listener->r_win_base) )
        {
            DebugMessage(DEBUG_STREAM_STATE, "FIN inside r_win_base, bailing\n");
            goto dupfin;
        }
        else
        {
            // need substate since we don't change state immediately
            if ( (talker->get_tcp_state() >= TcpStreamTracker::TCP_ESTABLISHED )
                && !( talker->s_mgr.sub_state & SUB_FIN_SENT ) )
            {
                talker->set_snd_nxt(talker->get_snd_nxt() + 1);

                //--------------------------------------------------
                // FIXIT-L don't bump r_nxt_ack unless FIN is in seq
                // because it causes bogus 129:5 cases
                // but doing so causes extra gaps
                //if ( SEQ_EQ(tsd.end_seq, listener->r_nxt_ack) )
                listener->r_nxt_ack++;
                //--------------------------------------------------

                talker->s_mgr.sub_state |= SUB_FIN_SENT;

                if ( ( listener->flush_policy != STREAM_FLPOLICY_ON_ACK )
                    && ( listener->flush_policy != STREAM_FLPOLICY_ON_DATA )
                    && listener->normalizer->is_tcp_ips_enabled() )
                {
                    tsd.get_pkt()->packet_flags |= PKT_PDU_TAIL;
                }
            }
            switch (talker->get_tcp_state())
            {
            case TcpStreamTracker::TCP_SYN_RECV:
            case TcpStreamTracker::TCP_ESTABLISHED:
                if ( talker->s_mgr.state_queue == TcpStreamTracker::TCP_CLOSE_WAIT )
                    talker->s_mgr.state_queue = TcpStreamTracker::TCP_CLOSING;

                talker->set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT1);
                EndOfFileHandle(tsd.get_pkt() );

                if ( !tsd.get_pkt()->dsize )
                    listener->reassembler->flush_on_data_policy(tsd.get_pkt() );

                update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
                break;

            case TcpStreamTracker::TCP_CLOSE_WAIT:
                talker->set_tcp_state(TcpStreamTracker::TCP_LAST_ACK);
                break;

            case TcpStreamTracker::TCP_FIN_WAIT1:
                if (!tsd.get_pkt()->dsize)
                    retransmit_handle(tsd.get_pkt() );
                break;

            default:
                /* all other states stay where they are */
                break;
            }

            if ((talker->get_tcp_state() == TcpStreamTracker::TCP_FIN_WAIT1) ||
                (talker->get_tcp_state() == TcpStreamTracker::TCP_LAST_ACK))
            {
                uint32_t end_seq = (flow->get_session_flags() & SSNFLAG_MIDSTREAM)
                    ? tsd.get_end_seq() - 1 : tsd.get_end_seq();

                if ((listener->s_mgr.expected_flags == TH_ACK) && SEQ_GEQ(end_seq,
                    listener->s_mgr.transition_seq))
                {
                    DebugMessage(DEBUG_STREAM_STATE, "FIN beyond previous, ignoring\n");
                    tel->set_tcp_event(EVENT_BAD_FIN);
                    listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
                    pkt_action_mask |= ACTION_BAD_PKT;
                    return;
                }
            }

            switch ( listener->get_tcp_state() )
            {
            case TcpStreamTracker::TCP_ESTABLISHED:
                listener->s_mgr.state_queue = TcpStreamTracker::TCP_CLOSE_WAIT;
                listener->s_mgr.transition_seq = tsd.get_end_seq() + 1;
                listener->s_mgr.expected_flags = TH_ACK;
                break;

            case TcpStreamTracker::TCP_FIN_WAIT1:
                listener->s_mgr.state_queue = TcpStreamTracker::TCP_CLOSING;
                listener->s_mgr.transition_seq = tsd.get_end_seq() + 1;
                listener->s_mgr.expected_flags = TH_ACK;
                break;

            case TcpStreamTracker::TCP_FIN_WAIT2:
                listener->s_mgr.state_queue = TcpStreamTracker::TCP_TIME_WAIT;
                listener->s_mgr.transition_seq = tsd.get_end_seq() + 1;
                listener->s_mgr.expected_flags = TH_ACK;
                break;

            default:
                // FIXIT - put this here quickly to make compiler happy, what should
                // be done when not in one of the 3 states above?
                DebugMessage(DEBUG_STREAM_STATE, "No Action In This State\n");
                break;
            }
        }
    }

dupfin:

    DebugFormat(DEBUG_STREAM_STATE, "   %s [talker] state: %s\n", t,
        tcp_state_names[talker->get_tcp_state()]);
    DebugFormat(DEBUG_STREAM_STATE, "   %s state: %s(%d)\n", l,
        tcp_state_names[listener->get_tcp_state()], listener->get_tcp_state());

    // handle TIME_WAIT timer stuff
    if (!flow->two_way_traffic() &&
        (talker->get_tcp_state() >= TcpStreamTracker::TCP_FIN_WAIT1 || listener->get_tcp_state() >=
        TcpStreamTracker::TCP_FIN_WAIT1))
    {
        if (tcph->is_fin() && tcph->is_ack())
        {
            if (talker->get_tcp_state() >= TcpStreamTracker::TCP_FIN_WAIT1)
                talker->set_tcp_state(TcpStreamTracker::TCP_CLOSED);

            if (listener->get_tcp_state() >= TcpStreamTracker::TCP_FIN_WAIT1)
                listener->set_tcp_state(TcpStreamTracker::TCP_CLOSED);

            listener->flags |= TF_FORCE_FLUSH;
        }
    }

    if ( ( talker->get_tcp_state() == TcpStreamTracker::TCP_TIME_WAIT &&
        listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSED)
        || (listener->get_tcp_state() == TcpStreamTracker::TCP_TIME_WAIT &&
        talker->get_tcp_state() == TcpStreamTracker::TCP_CLOSED)
        || (listener->get_tcp_state() == TcpStreamTracker::TCP_TIME_WAIT &&
        talker->get_tcp_state() ==  TcpStreamTracker::TCP_TIME_WAIT)
        || (!flow->two_way_traffic() && (talker->get_tcp_state() == TcpStreamTracker::TCP_CLOSED ||
        listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSED)))
    {
        // The last ACK is a part of the session. Delete the session after processing is complete.
        cleanup_session(0, tsd.get_pkt() );
        flow->session_state |= STREAM_STATE_CLOSED;
        pkt_action_mask |= ACTION_LWSSN_CLOSED;
        return;
    }
    else if ( listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSED
        && talker->get_tcp_state() == TcpStreamTracker::TCP_SYN_SENT )
    {
        if ( tcph->is_syn_only() )
            flow->set_expire(tsd.get_pkt(), config->session_timeout);
    }
}

//-------------------------------------------------------------------------
// TcpSession methods
//-------------------------------------------------------------------------

TcpSession::TcpSession(Flow* flow) :
    Session(flow), config(nullptr), client(new TcpTracker(true) ),
    server(new TcpTracker(false) ), ecn(0), ingress_index(0),
    ingress_group(0), egress_index(0), egress_group(0), daq_flags(0), address_space_id(0),
    pkt_action_mask(ACTION_NOTHING), require_3whs(true), no_3whs(false)
{
    lws_init = tcp_init = false;
    new_ssn = false;

    tel = new TcpEventLogger;

    // initialize stream tracker state machine...
    new TcpStateNone(tsm, *this);
    new TcpStateClosed(tsm, *this);
    new TcpStateListen(tsm, *this);
    new TcpStateSynSent(tsm, *this);
    new TcpStateSynRecv(tsm, *this);
    new TcpStateEstablished(tsm, *this);
    new TcpStateFinWait1(tsm, *this);
    new TcpStateFinWait2(tsm, *this);
    new TcpStateClosing(tsm, *this);
    new TcpStateCloseWait(tsm, *this);
    new TcpStateLastAck(tsm, *this);
    new TcpStateTimeWait(tsm, *this);
}

TcpSession::~TcpSession(void)
{
    if (tcp_init)
    {
        clear_session(1);

        delete client;
        delete server;
    }

    delete tel;
}

void TcpSession::reset(void)
{
    if (tcp_init)
        clear_session(2);
}

bool TcpSession::setup(Packet*)
{
    // FIXIT-L this it should not be necessary to reset here
    reset();

    client->init_tracker( );
    server->init_tracker( );
    lws_init = tcp_init = false;
    no_3whs = false;
    pkt_action_mask = ACTION_NOTHING;
    ecn = 0;
    ingress_index = egress_index = 0;
    ingress_group = egress_group = 0;
    daq_flags = address_space_id = 0;

    SESSION_STATS_ADD(tcpStats);
    return true;
}

void TcpSession::cleanup(void)
{
    // this flushes data and then calls TcpSessionClear()
    cleanup_session(1);
}

void TcpSession::clear(void)
{
    if ( tcp_init )
        // this does NOT flush data
        clear_session(true);
}

void TcpSession::restart(Packet* p)
{
    // sanity check since this is called externally
    assert(p->ptrs.tcph);

    TcpTracker* talker, * listener;

    if (p->packet_flags & PKT_FROM_SERVER)
    {
        talker = server;
        listener = client;
    }
    else
    {
        talker = client;
        listener = server;
    }

    // FIXIT-H on data / on ack must be based on flush policy
    if (p->dsize > 0)
        listener->reassembler->flush_on_data_policy(p);

    if (p->ptrs.tcph->is_ack())
        talker->reassembler->flush_on_ack_policy(p);
}

void TcpSession::print(void)
{
    char buf[64];

    LogMessage("TcpSession:\n");
    sfip_ntop(&flow->server_ip, buf, sizeof(buf));
    LogMessage("    server IP:          %s\n", buf);
    sfip_ntop(&flow->client_ip, buf, sizeof(buf));
    LogMessage("    client IP:          %s\n", buf);
    LogMessage("    server port:        %d\n", flow->server_port);
    LogMessage("    client port:        %d\n", flow->client_port);
    LogMessage("    flags:              0x%X\n", flow->get_session_flags());
    LogMessage("Client Tracker:\n");
    client->print();
    LogMessage("Server Tracker:\n");
    server->print();
}

void TcpSession::set_splitter(bool to_server, StreamSplitter* ss)
{
    TcpTracker* trk = ( to_server ) ? server : client;

    trk->set_splitter(ss);
}

StreamSplitter* TcpSession::get_splitter(bool to_server)
{
    if ( to_server )
        return server->splitter;
    else
        return client->splitter;
}

void TcpSession::flush_server(Packet* p)
{
    server->flags |= TF_FORCE_FLUSH;

    // If rebuilt packet, don't flush now because we'll overwrite the packet being processed.
    if ( p->packet_flags & PKT_REBUILT_STREAM )
    {
        // We'll check & clear the TF_FORCE_FLUSH next time through
        return;
    }

    // Need to convert the addresses to network order
    if ( server->reassembler->flush_stream(p, PKT_FROM_SERVER) )
        server->reassembler->purge_flushed_ackd( );

    server->flags &= ~TF_FORCE_FLUSH;
}

void TcpSession::flush_client(Packet* p)
{
    client->flags |= TF_FORCE_FLUSH;

    // If rebuilt packet, don't flush now because we'll overwrite the packet being processed.
    if ( p->packet_flags & PKT_REBUILT_STREAM )
    {
        // We'll check & clear the TF_FORCE_FLUSH next time through
        return;
    }

    if ( client->reassembler->flush_stream(p, PKT_FROM_CLIENT) )
        client->reassembler->purge_flushed_ackd( );

    client->flags &= ~TF_FORCE_FLUSH;
}

void TcpSession::flush_listener(Packet* p)
{
    TcpTracker* listener = nullptr;
    uint32_t dir = 0;

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if ( p->packet_flags & PKT_FROM_SERVER )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Flushing listener on packet from server\n");
        listener = client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }
    else if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Flushing listener on packet from client\n");
        listener = server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }

    if ( dir != 0 )
    {
        listener->flags |= TF_FORCE_FLUSH;
        if ( listener->reassembler->flush_stream(p, dir) )
            listener->reassembler->purge_flushed_ackd( );

        listener->flags &= ~TF_FORCE_FLUSH;
    }
}

void TcpSession::flush_talker(Packet* p)
{
    TcpTracker* talker = nullptr;
    uint32_t dir = 0;

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if ( p->packet_flags & PKT_FROM_SERVER )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Flushing talker on packet from server\n");
        talker = server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }
    else if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        DebugMessage(DEBUG_STREAM_STATE, "Flushing talker on packet from client\n");
        talker = client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }

    if (dir != 0)
    {
        talker->flags |= TF_FORCE_FLUSH;
        if ( talker->reassembler->flush_stream(p, dir) )
            talker->reassembler->purge_flushed_ackd( );

        talker->flags &= ~TF_FORCE_FLUSH;
    }
}

// FIXIT add alert and check alerted go away when we finish
// packet / PDU split because PDU rules won't run on raw packets
bool TcpSession::add_alert(Packet* p, uint32_t gid, uint32_t sid)
{
    TcpTracker* st;
    StreamAlertInfo* ai;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = server;
    else
        st = client;

    if (st->alert_count >= MAX_SESSION_ALERTS)
        return false;

    ai = st->alerts + st->alert_count;
    ai->gid = gid;
    ai->sid = sid;
    ai->seq = 0;

    st->alert_count++;

    return true;
}

bool TcpSession::check_alerted(Packet* p, uint32_t gid, uint32_t sid)
{
    /* If this is not a rebuilt packet, no need to check further */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return false;

    TcpTracker* st;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = server;
    else
        st = client;

    for (int i = 0; i < st->alert_count; i++)
    {
        /*  This is a rebuilt packet and if we've seen this alert before,
         *  return that we have previously alerted on original packet.
         */
        if (st->alerts[i].gid == gid && st->alerts[i].sid == sid)
        {
            return true;
        }
    }

    return false;
}

int TcpSession::update_alert(Packet* p, uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
    TcpTracker* st;
    int i;
    uint32_t seq_num;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = server;
    else
        st = client;

    seq_num = 0;

    for (i = 0; i < st->alert_count; i++)
    {
        StreamAlertInfo* ai = st->alerts + i;

        if (ai->gid == gid && ai->sid == sid && SEQ_EQ(ai->seq, seq_num))
        {
            ai->event_id = event_id;
            ai->event_second = event_second;
            return 0;
        }
    }

    return -1;
}

void TcpSession::set_extra_data(Packet* p, uint32_t xid)
{
    TcpTracker* st;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = server;
    else
        st = client;

    st->reassembler->set_xtradata_mask(st->reassembler->get_xtradata_mask() | BIT(xid) );
}

void TcpSession::clear_extra_data(Packet* p, uint32_t xid)
{
    TcpTracker* st;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = server;
    else
        st = client;

    if (xid)
        st->reassembler->set_xtradata_mask(st->reassembler->get_xtradata_mask() & ~BIT(xid) );
    else
        st->reassembler->set_xtradata_mask(0);
}

uint8_t TcpSession::get_reassembly_direction(void)
{
    uint8_t dir = SSN_DIR_NONE;

    if (server->flush_policy != STREAM_FLPOLICY_IGNORE)
    {
        dir |= SSN_DIR_FROM_CLIENT;
    }

    if (client->flush_policy != STREAM_FLPOLICY_IGNORE)
    {
        dir |= SSN_DIR_FROM_SERVER;
    }

    return dir;
}

bool TcpSession::is_sequenced(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if (server->flags & (TF_MISSING_PREV_PKT | TF_MISSING_PKT))
            return false;
    }

    if (dir & SSN_DIR_FROM_SERVER)
    {
        if (client->flags & (TF_MISSING_PREV_PKT | TF_MISSING_PKT))
            return false;
    }

    return true;
}

/* This will falsely return SSN_MISSING_BEFORE on the first reassembed
 * packet if reassembly for this direction was set mid-session */
uint8_t TcpSession::missing_in_reassembled(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if ((server->flags & TF_MISSING_PKT)
            && (server->flags & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (server->flags & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (server->flags & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }
    else if (dir & SSN_DIR_FROM_SERVER)
    {
        if ((client->flags & TF_MISSING_PKT)
            && (client->flags & TF_MISSING_PREV_PKT))
            return SSN_MISSING_BOTH;
        else if (client->flags & TF_MISSING_PREV_PKT)
            return SSN_MISSING_BEFORE;
        else if (client->flags & TF_MISSING_PKT)
            return SSN_MISSING_AFTER;
    }

    return SSN_MISSING_NONE;
}

bool TcpSession::are_packets_missing(uint8_t dir)
{
    if (dir & SSN_DIR_FROM_CLIENT)
    {
        if (server->flags & TF_PKT_MISSED)
            return true;
    }

    if (dir & SSN_DIR_FROM_SERVER)
    {
        if (client->flags & TF_PKT_MISSED)
            return true;
    }

    return false;
}

void TcpSession::update_direction(char dir, const sfip_t* ip, uint16_t port)
{
    sfip_t tmpIp;
    uint16_t tmpPort;
    TcpTracker* tracker;

    if (sfip_equals(&flow->client_ip, ip) && (flow->client_port == port))
    {
        if ((dir == SSN_DIR_FROM_CLIENT) && (flow->ssn_state.direction == FROM_CLIENT))
        {
            /* Direction already set as client */
            return;
        }
    }
    else if (sfip_equals(&flow->server_ip, ip) && (flow->server_port == port))
    {
        if ((dir == SSN_DIR_FROM_SERVER) && (flow->ssn_state.direction == FROM_SERVER))
        {
            /* Direction already set as server */
            return;
        }
    }

    /* Swap them -- leave flow->ssn_state.direction the same */
    tmpIp = flow->client_ip;
    tmpPort = flow->client_port;
    flow->client_ip = flow->server_ip;
    flow->client_port = flow->server_port;
    flow->server_ip = tmpIp;
    flow->server_port = tmpPort;

    SwapPacketHeaderFoo( );
    tracker = client;
    client = server;
    server = tracker;
}

void TcpSession::SetPacketHeaderFoo(const Packet* p)
{
    if ( daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING )
    {
        ingress_index = p->pkth->ingress_index;
        ingress_group = p->pkth->ingress_group;
        // ssn egress may be unknown, but will be correct
        egress_index = p->pkth->egress_index;
        egress_group = p->pkth->egress_group;
    }
    else if ( p->packet_flags & PKT_FROM_CLIENT )
    {
        ingress_index = p->pkth->ingress_index;
        ingress_group = p->pkth->ingress_group;
        // ssn egress not always correct here
    }
    else
    {
        // ssn ingress not always correct here
        egress_index = p->pkth->ingress_index;
        egress_group = p->pkth->ingress_group;
    }
    daq_flags = p->pkth->flags;
    address_space_id = p->pkth->address_space_id;
}

void TcpSession::GetPacketHeaderFoo(DAQ_PktHdr_t* pkth, uint32_t dir)
{
    if ( (dir & PKT_FROM_CLIENT) || (daq_flags & DAQ_PKT_FLAG_NOT_FORWARDING) )
    {
        pkth->ingress_index = ingress_index;
        pkth->ingress_group = ingress_group;
        pkth->egress_index = egress_index;
        pkth->egress_group = egress_group;
    }
    else
    {
        pkth->ingress_index = egress_index;
        pkth->ingress_group = egress_group;
        pkth->egress_index = ingress_index;
        pkth->egress_group = ingress_group;
    }
    pkth->opaque = 0;
    pkth->flags = daq_flags;
    pkth->address_space_id = address_space_id;
}

void TcpSession::SwapPacketHeaderFoo(void)
{
    if ( egress_index != DAQ_PKTHDR_UNKNOWN )
    {
        int32_t save_ingress_index;
        int32_t save_ingress_group;

        save_ingress_index = ingress_index;
        save_ingress_group = ingress_group;
        ingress_index = egress_index;
        ingress_group = egress_group;
        egress_index = save_ingress_index;
        egress_group = save_ingress_group;
    }
}

/*
 * Main entry point for TCP
 */
int TcpSession::process(Packet* p)
{
    Profile profile(s5TcpPerfStats);

    DEBUG_WRAP(
        char flagbuf[9];
        CreateTCPFlagString(p->ptrs.tcph, flagbuf);
        DebugFormat((DEBUG_STREAM|DEBUG_STREAM_STATE),
        "Got TCP Packet 0x%X:%d ->  0x%X:%d %s\nseq: 0x%X   ack:0x%X  dsize: %u\n",
        p->ptrs.ip_api.get_src(), p->ptrs.sp, p->ptrs.ip_api.get_dst(), p->ptrs.dp, flagbuf,
        ntohl(p->ptrs.tcph->th_seq), ntohl(p->ptrs.tcph->th_ack), p->dsize);
        );

    // FIXIT-L can't get here without protocol being set to TCP, is this really needed??
    if (flow->protocol != PktType::TCP)
    {
        DebugMessage(DEBUG_STREAM_STATE, "Lightweight session not TCP on TCP packet\n");
        return ACTION_NOTHING;
    }

    if (stream.blocked_session(flow, p) || (flow->session_state & STREAM_STATE_IGNORE))
        return ACTION_NOTHING;

    // FIXIT-L expected flow should be checked by flow_con before we get here
    // harmonize this with that and the checks above
    char ignore = flow_con->expected_flow(flow, p);
    if (ignore)
    {
        server->flush_policy = STREAM_FLPOLICY_IGNORE;
        client->flush_policy = STREAM_FLPOLICY_IGNORE;
        return ACTION_NOTHING;
    }

    TcpSegmentDescriptor tsd(flow, p, tel);
    if (!lws_init)
    {
        // FIXIT - should only do ths once...
        if (config == nullptr )
        {
            config = get_tcp_cfg(flow->ssn_server);
            require_3whs = config->require_3whs();
            client->set_require_3whs(require_3whs);
            server->set_require_3whs(require_3whs);
        }
        set_os_policy( );

        // FIXIT most of this now looks out of place or redundant
        if ( require_3whs )
        {
            if (p->ptrs.tcph->is_syn_only())
            {
                /* SYN only */
                flow->session_state = STREAM_STATE_SYN;
            }
            else
            {
                // If we're within the "startup" window, try to handle
                // this packet as midstream pickup -- allows for
                // connections that already existed before snort started.
                if (config->midstream_allowed(p))
                    goto midstream_pickup_allowed;

                // Do nothing with this packet since we require a 3-way ;)
                DEBUG_WRAP(
                    DebugMessage(DEBUG_STREAM_STATE,
                    "Stream: Requiring 3-way Handshake, but failed to retrieve session"
                    " object for non SYN packet.\n");
                    );
                if ( !p->ptrs.tcph->is_syn_only() && !p->ptrs.tcph->is_rst() && !no_3whs )
                {
                    tel->EventNo3whs();
                    no_3whs = true;
                }
#ifdef REG_TEST
                S5TraceTCP(p, flow, &tsd, 1);
#endif
                return 0;
            }
        }
        else
        {
midstream_pickup_allowed:
            if ( !p->ptrs.tcph->is_syn_ack()
                && !p->dsize
                && !(tsd.has_wscale() & TF_WSCALE) )
            {
#ifdef REG_TEST
                S5TraceTCP(p, flow, &tsd, 1);
#endif
                return 0;
            }

            if (p->ptrs.tcph->is_syn())
                flow->session_state |= STREAM_STATE_SYN;
        }
        lws_init = true;
    }

    // Check if the session is expired. Should be done before we do something with
    // the packet...Insert a packet, or handle state change SYN, FIN, RST, etc.
    if (stream.expired_session(flow, p))
    {
        /* Session is timed out */
        if (flow->get_session_flags() & SSNFLAG_RESET)
        {
            /* If this one has been reset, delete the TCP
             * portion, and start a new. */
            cleanup_session(1);
        }
        else
        {
            DebugMessage(DEBUG_STREAM_STATE, "Stream TCP session timedout!\n");

            /* Not reset, simply time'd out.  Clean it up */
            cleanup_session(1);
        }
        tcpStats.timeouts++;
    }

    // FIXIT - need to do something here to handle check for need to swap trackers
    new_ssn = false;
    if ( tsm.eval(tsd, *server) )
        tsm.eval(tsd, *client);

    // FIXIT - this should change once tcp sm fully implemented
    pkt_action_mask = ACTION_NOTHING;
    tel->clear_tcp_events();

    if ( tcp_init || tsd.get_pkt()->dsize)
        process_tcp_packet(tsd);
    // FIXIT - end

    tel->log_tcp_events();

    DebugMessage(DEBUG_STREAM_STATE,
        "Finished Stream TCP cleanly!\n---------------------------------------------------\n");

    if (!(pkt_action_mask & ACTION_LWSSN_CLOSED))
    {
        flow->markup_packet_flags(p);
        flow->set_expire(p, config->session_timeout);
    }

    if (pkt_action_mask & ACTION_DISABLE_INSPECTION)
    {
        DisableInspection(p);

        DebugFormat(DEBUG_STREAM_STATE,
            "Stream Ignoring packet from %d. Session marked as ignore\n",
            p->packet_flags & PKT_FROM_SERVER ? "server" : "client");
    }

    S5TraceTCP(p, flow, &tsd, 0);
    return 0;
}

void TcpSession::flush(void)
{
    if ( ( server->reassembler->is_segment_pending_flush() ) ||
        (client->reassembler->is_segment_pending_flush() ) )
    {
        server->reassembler->flush_queued_segments(flow, false);
        client->reassembler->flush_queued_segments(flow, false);
    }
}

void TcpSession::start_proxy(void)
{
    config->policy = StreamPolicy::OS_PROXY;
}

//-------------------------------------------------------------------------
// tcp module stuff
//-------------------------------------------------------------------------

void TcpSession::set_memcap(Memcap& mc)
{
    tcp_memcap = &mc;
}

void TcpSession::sinit(void)
{
    s5_pkt = PacketManager::encode_new();
    //AtomSplitter::init();  // FIXIT-L PAF implement
}

void TcpSession::sterm(void)
{
    if (s5_pkt)
    {
        PacketManager::encode_delete(s5_pkt);
        s5_pkt = nullptr;
    }
}

