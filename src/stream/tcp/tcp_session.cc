//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
#include "sfip/sf_ip.h"
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

DEBUG_WRAP(const char* t_name = NULL; const char* l_name = NULL; )

TcpSession::TcpSession(Flow* flow) : TcpStreamSession(flow)
{
    client = new TcpTracker(true);
    server = new TcpTracker(false);

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
        clear_session(1);

    delete client;
    delete server;
}

bool TcpSession::setup(Packet* p)
{
    TcpStreamSession::setup(p);

    SESSION_STATS_ADD(tcpStats);
    return true;
}

// FIXIT - once TcpReassembler interface is abstract class move this to base class
void TcpSession::restart(Packet* p)
{
    // sanity check since this is called externally
    assert(p->ptrs.tcph);

    TcpStreamTracker* talker, * listener;

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
    tel.log_internal_event(INTERNAL_EVENT_SESSION_DEL);

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
            if ( perfmon_config && ( perfmon_config->perf_flags & PERF_FLOWIP ) )
                perf_flow_ip->update_state(&flow->client_ip,
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

                if (perfmon_config  && (perfmon_config->perf_flags & PERF_FLOWIP))
                    perf_flow_ip->update_state(&flow->client_ip, &flow->server_ip,
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

            if ( perfmon_config && ( perfmon_config->perf_flags & PERF_FLOWIP ) )
                perf_flow_ip->update_state(&flow->client_ip,
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

bool TcpSession::flow_exceeds_config_thresholds(TcpSegmentDescriptor& tsd)
{
    if (listener->flush_policy == STREAM_FLPOLICY_IGNORE)
    {
        DebugMessage(DEBUG_STREAM_STATE, "Ignoring segment due to IGNORE flush_policy\n");
        return true;
    }

    if ( ( config->flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY ) && !flow->two_way_traffic() )
        return true;

    if ( config->max_consec_small_segs && ( tsd.get_seg_len() <
        config->max_consec_small_seg_size ) )
    {
        listener->small_seg_count++;

        if ( listener->small_seg_count > config->max_consec_small_segs )
        {
            /* Above threshold, log it...  in this TCP policy,
             * action controlled by preprocessor rule. */
            tel.set_tcp_event(EVENT_MAX_SMALL_SEGS_EXCEEDED);
            /* Reset counter, so we're not too noisy */
            listener->small_seg_count = 0;
        }
    }

    if ( config->max_queued_bytes
        && ( listener->reassembler->get_seg_bytes_total() > config->max_queued_bytes ) )
    {
        tcpStats.max_bytes++;
        return true;
    }

    if ( config->max_queued_segs
        && ( listener->reassembler->get_seg_count() + 1 > config->max_queued_segs ) )
    {
        tcpStats.max_segs++;
        return true;
    }

    return false;
}

void TcpSession::process_tcp_stream(TcpSegmentDescriptor& tsd)
{
    DebugFormat(DEBUG_STREAM_STATE, "In ProcessTcpStream(), %d bytes to queue\n",
        tsd.get_seg_len());

    if (tsd.get_pkt()->packet_flags & PKT_IGNORE)
        return;

    SetPacketHeaderFoo(tsd.get_pkt() );

    if ( flow_exceeds_config_thresholds(tsd) )
        return;

    DebugMessage(DEBUG_STREAM_STATE, "queuing segment\n");
    listener->reassembler->queue_packet_for_reassembly(tsd);

    // Alert if overlap limit exceeded
    if ( ( config->overlap_limit )
        && ( listener->reassembler->get_overlap_count() > config->overlap_limit ) )
    {
        tel.set_tcp_event(EVENT_EXCESSIVE_OVERLAP);
        listener->reassembler->set_overlap_count(0);
    }
}

int TcpSession::process_tcp_data(TcpSegmentDescriptor& tsd)
{
    Profile profile(s5TcpDataPerfStats);

    const tcp::TCPHdr* tcph = tsd.get_tcph();
    uint32_t seq = tsd.get_seg_seq();

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
        listener->r_nxt_ack = tsd.get_end_seq();

        if (tsd.get_seg_len() != 0)
        {
            if (!( flow->get_session_flags() & SSNFLAG_STREAM_ORDER_BAD))
                tsd.get_pkt()->packet_flags |= PKT_STREAM_ORDER_OK;

            process_tcp_stream(tsd);
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
            tsd.get_seg_seq(), listener->r_nxt_ack);

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

        if (tsd.get_seg_len() != 0)
        {
            if (!( flow->get_session_flags() & SSNFLAG_STREAM_ORDER_BAD))
            {
                if (!SEQ_LEQ((tsd.get_seg_seq() + tsd.get_seg_len()), listener->r_nxt_ack))
                    flow->set_session_flags(SSNFLAG_STREAM_ORDER_BAD);
            }
            process_tcp_stream(tsd);
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
        TcpStreamTracker* trk = client;
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

void TcpSession::update_timestamp_tracking(TcpSegmentDescriptor& tsd)
{
    talker->set_tf_flags(listener->normalizer->get_timestamp_flags());
    if (listener->normalizer->handling_timestamps()
        && SEQ_EQ(listener->r_nxt_ack, tsd.get_seg_seq()))
    {
        talker->set_ts_last_packet(tsd.get_pkt()->pkth->ts.tv_sec);
        talker->set_ts_last(tsd.get_ts());
    }
}

bool TcpSession::handle_syn_on_reset_session(TcpSegmentDescriptor& tsd)
{
    const tcp::TCPHdr* tcph = tsd.get_tcph();
    if ( ( listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSED )
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
            listener->normalizer->ecn_tracker( (tcp::TCPHdr*)tcph, config->require_3whs() );
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
            listener->normalizer->ecn_tracker( (tcp::TCPHdr*)tcph, config->require_3whs() );
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
        if ( talker && ( talker->get_tf_flags() & TF_FORCE_FLUSH ) )
        {
            flush_talker(tsd.get_pkt() );
            talker->clear_tf_flags(TF_FORCE_FLUSH);
        }

        if ( listener && ( listener->get_tf_flags() & TF_FORCE_FLUSH ) )
        {
            flush_listener(tsd.get_pkt() );
            listener->clear_tf_flags(TF_FORCE_FLUSH);
        }

        tsd.get_pkt()->packet_flags |= PKT_IGNORE;
        pkt_action_mask |= ACTION_DISABLE_INSPECTION;
    }
}

void TcpSession::handle_data_on_syn(TcpSegmentDescriptor& tsd)
{
    /* MacOS accepts data on SYN, so don't alert if policy is MACOS */
    if (talker->normalizer->get_os_policy() == StreamPolicy::OS_MACOS)
    {
        handle_data_segment(tsd);
    }
    else
    {
        // remove data on SYN
        listener->normalizer->trim_syn_payload(tsd);

        if (Normalize_GetMode(NORM_TCP_TRIM_SYN) != NORM_MODE_ON)
        {
            DebugMessage(DEBUG_STREAM_STATE, "Got data on SYN packet, not processing it\n");
            tel.set_tcp_event(EVENT_DATA_ON_SYN);
            pkt_action_mask |= ACTION_BAD_PKT;
        }
    }
}

void TcpSession::update_session_on_rst(TcpSegmentDescriptor& tsd, bool flush)
{
    if ( flush )
    {
        flush_listener(tsd.get_pkt());
        flush_talker(tsd.get_pkt());
        set_splitter(true, nullptr);
        set_splitter(false, nullptr);
        flow->free_application_data();
    }

    talker->update_on_rst_sent( );
}

void TcpSession::update_paws_timestamps(TcpSegmentDescriptor& tsd)
{
    // update PAWS timestamps
    DebugFormat(DEBUG_STREAM_STATE, "PAWS update tsd.seq %lu > listener->r_win_base %lu\n",
        tsd.get_seg_seq(), listener->r_win_base);

    if ( listener->normalizer->handling_timestamps()
        && SEQ_EQ(listener->r_win_base, tsd.get_seg_seq() ) )
    {
        if ( ( (int32_t)(tsd.get_ts() - talker->get_ts_last() ) >= 0 )
            ||
            ( ( uint32_t )tsd.get_pkt()->pkth->ts.tv_sec
            >= talker->get_ts_last_packet() + PAWS_24DAYS ) )
        {
            DebugMessage(DEBUG_STREAM_STATE, "updating timestamps...\n");
            talker->set_ts_last(tsd.get_ts());
            talker->set_ts_last_packet(tsd.get_pkt()->pkth->ts.tv_sec);
        }
    }
    else
    {
        DebugMessage(DEBUG_STREAM_STATE, "not updating timestamps...\n");
    }
}

void TcpSession::check_for_session_hijack(TcpSegmentDescriptor& tsd)
{
#ifdef DAQ_PKT_FLAG_PRE_ROUTING
    if (!(tsd.get_pkt()->pkth->flags & DAQ_PKT_FLAG_PRE_ROUTING))
#endif
    {
        uint32_t event_code = 0;

        if ( tsd.get_pkt()->is_eth() )
        {
            // if flag is set, gauranteed to have an eth layer
            Packet* p = tsd.get_pkt();
            const eth::EtherHdr* eh = layer::get_eth_layer(p);
            bool t_hijack = !talker->compare_mac_addresses(eh->ether_src);
            bool l_hijack = !listener->compare_mac_addresses(eh->ether_dst);

            // if both seem hijacked then swap src/dst check, it that matches probably a tap
            if ( ( t_hijack & l_hijack ) &&
                ( talker->compare_mac_addresses(eh->ether_dst) &&
                listener->compare_mac_addresses(eh->ether_src) ) )
                return;

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

            if (event_code)
                tel.set_tcp_event(event_code);
        }
    }
}

bool TcpSession::check_for_window_slam(TcpSegmentDescriptor& tsd)
{
    if ( config->max_window && (tsd.get_seg_wnd() > config->max_window ) )
    {
        DebugMessage(DEBUG_STREAM_STATE,
            "Got window that was beyond the allowed policy value, bailing\n");
        /* got a window too large, alert! */
        tel.set_tcp_event(EVENT_WINDOW_TOO_LARGE);
        inc_tcp_discards();
        listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
        pkt_action_mask |= ACTION_BAD_PKT;
        return true;
    }
    else if ((tsd.get_pkt()->packet_flags & PKT_FROM_CLIENT)
        && (tsd.get_seg_wnd() <= SLAM_MAX)
        && (tsd.get_seg_ack() == listener->get_iss() + 1)
        && !( tsd.get_tcph()->is_fin() | tsd.get_tcph()->is_rst() )
        && !(flow->get_session_flags() & SSNFLAG_MIDSTREAM))
    {
        DebugMessage(DEBUG_STREAM_STATE, "Window slammed shut!\n");
        /* got a window slam alert! */
        tel.set_tcp_event(EVENT_WINDOW_SLAM);
        inc_tcp_discards();

        if (listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK))
        {
            pkt_action_mask |= ACTION_BAD_PKT;
            return true;
        }
    }

    return false;
}

void TcpSession::mark_packet_for_drop(TcpSegmentDescriptor& tsd)
{
    listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
    set_pkt_action_flag(ACTION_BAD_PKT);
}

void TcpSession::handle_data_segment(TcpSegmentDescriptor& tsd)
{
    DebugFormat(DEBUG_STREAM_STATE, "   %s state: %s(%d) getting data\n",
        l_name, tcp_state_names[listener->get_tcp_state()], listener->get_tcp_state());

    DebugFormat(DEBUG_STREAM_STATE, "Queuing data on listener, t %s, l %s...\n",
        flush_policy_names[talker->flush_policy],
        flush_policy_names[listener->flush_policy]);

    if ( TcpStreamTracker::TCP_CLOSED != talker->get_tcp_state() )
    {
        // FIXIT - move this to normalizer base class, handle OS_PROXY in derived class
        if (config->policy != StreamPolicy::OS_PROXY)
        {
            /* check for valid seqeuence/retrans */
            if (!listener->is_segment_seq_valid(tsd) )
                return;

            // these normalizations can't be done if we missed setup. and
            // window is zero in one direction until we've seen both sides.
            if (!(flow->get_session_flags() & SSNFLAG_MIDSTREAM) && flow->two_way_traffic())
            {
                // sender of syn w/mss limits payloads from peer since we store mss on
                // sender side, use listener mss same reasoning for window size
                TcpStreamTracker* st = listener;

                // trim to fit in window and mss as needed
                st->normalizer->trim_win_payload(tsd, (st->r_win_base + st->get_snd_wnd() -
                        st->r_nxt_ack));

                if (st->get_mss())
                    st->normalizer->trim_mss_payload(tsd, st->get_mss());

                st->normalizer->ecn_stripper(tsd.get_pkt());
            }
        }

        // dunno if this is RFC but fragroute testing expects it  for the record,
        // I've seen FTP data sessions that send data packets with no tcp flags set
        if ((tsd.get_tcph()->th_flags != 0) or (config->policy == StreamPolicy::OS_LINUX)
                or (config->policy == StreamPolicy::OS_PROXY))
        {
            process_tcp_data(tsd);
        }
        else
        {
            tel.set_tcp_event(EVENT_DATA_WITHOUT_FLAGS);
            listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK);
        }
    }

    listener->reassembler->flush_on_data_policy(tsd.get_pkt());
}

TcpStreamTracker::TcpState TcpSession::get_talker_state(void)
{
    return talker->get_tcp_state();
}

TcpStreamTracker::TcpState TcpSession::get_listener_state(void)
{
    return listener->get_tcp_state();
}

void TcpSession::check_for_repeated_syn(TcpSegmentDescriptor& tsd)
{
    uint32_t action = ACTION_NOTHING;
    if (!SEQ_EQ(tsd.get_seg_seq(), talker->get_iss())
        && listener->normalizer->packet_dropper(tsd, NORM_TCP_BLOCK))
        action = ACTION_BAD_PKT;
    else if (talker->get_tcp_state() >= TcpStreamTracker::TCP_ESTABLISHED)
        action = listener->normalizer->handle_repeated_syn(tsd);

    if (action != ACTION_NOTHING)
    {
        /* got a bad SYN on the session, alert! */
        tel.set_tcp_event(EVENT_SYN_ON_EST);
        pkt_action_mask |= action;
    }
}

void TcpSession::flush_server(Packet* p)
{
    server->set_tf_flags(TF_FORCE_FLUSH);

    // If rebuilt packet, don't flush now because we'll overwrite the packet being processed.
    if ( p->packet_flags & PKT_REBUILT_STREAM )
    {
        // We'll check & clear the TF_FORCE_FLUSH next time through
        return;
    }

    // Need to convert the addresses to network order
    if ( server->reassembler->flush_stream(p, PKT_FROM_SERVER) )
        server->reassembler->purge_flushed_ackd( );

    server->clear_tf_flags(TF_FORCE_FLUSH);
}

void TcpSession::flush_client(Packet* p)
{
    client->set_tf_flags(TF_FORCE_FLUSH);

    // If rebuilt packet, don't flush now because we'll overwrite the packet being processed.
    if ( p->packet_flags & PKT_REBUILT_STREAM )
    {
        // We'll check & clear the TF_FORCE_FLUSH next time through
        return;
    }

    if ( client->reassembler->flush_stream(p, PKT_FROM_CLIENT) )
        client->reassembler->purge_flushed_ackd( );

    client->clear_tf_flags(TF_FORCE_FLUSH);
}

void TcpSession::flush_listener(Packet* p)
{
    TcpStreamTracker* listener = nullptr;
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
        listener->set_tf_flags(TF_FORCE_FLUSH);
        if ( listener->reassembler->flush_stream(p, dir) )
            listener->reassembler->purge_flushed_ackd( );

        listener->clear_tf_flags(TF_FORCE_FLUSH);
    }
}

void TcpSession::flush_talker(Packet* p)
{
    TcpStreamTracker* talker = nullptr;
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
        talker->set_tf_flags(TF_FORCE_FLUSH);
        if ( talker->reassembler->flush_stream(p, dir) )
            talker->reassembler->purge_flushed_ackd( );

        talker->clear_tf_flags(TF_FORCE_FLUSH);
    }
}

void TcpSession::set_extra_data(Packet* p, uint32_t xid)
{
    TcpStreamTracker* st;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = server;
    else
        st = client;

    st->reassembler->set_xtradata_mask(st->reassembler->get_xtradata_mask() | BIT(xid) );
}

void TcpSession::clear_extra_data(Packet* p, uint32_t xid)
{
    TcpStreamTracker* st;

    if (sfip_equals(p->ptrs.ip_api.get_src(), &flow->client_ip))
        st = server;
    else
        st = client;

    if (xid)
        st->reassembler->set_xtradata_mask(st->reassembler->get_xtradata_mask() & ~BIT(xid) );
    else
        st->reassembler->set_xtradata_mask(0);
}

static inline void set_window_scale(TcpStreamTracker& talker, TcpStreamTracker& listener,
    TcpSegmentDescriptor& tsd)
{
    // scale the window.  Only if BOTH client and server specified wscale option as part
    // of 3-way handshake.  This is per RFC 1323.
    if ( ( talker.get_tf_flags() & TF_WSCALE ) && ( listener.get_tf_flags() & TF_WSCALE ) )
        tsd.scale_seg_wnd(talker.get_wscale() );
}

void TcpSession::do_packet_analysis_post_checks(Packet* p)
{
    tel.log_tcp_events();

    if (!(pkt_action_mask & ACTION_LWSSN_CLOSED))
    {
        flow->markup_packet_flags(p);
        flow->set_expire(p, config->session_timeout);
    }
    if (pkt_action_mask & ACTION_DISABLE_INSPECTION)
    {
        DisableInspection();

        DebugFormat(DEBUG_STREAM_STATE,
            "Stream Ignoring packet from %d. Session marked as ignore\n",
            p->packet_flags & PKT_FROM_SERVER ? "server" : "client");
    }
}

// FIXIT - can flow do these checks before calling stream tcp?
bool TcpSession::is_flow_handling_packets(Packet* p)
{
    bool flow_ready = true;

    // FIXIT-L can't get here without protocol being set to TCP, is this really needed??
    if (flow->pkt_type != PktType::TCP)
    {
        DebugMessage(DEBUG_STREAM_STATE, "Lightweight session not TCP on TCP packet\n");
        flow_ready = false;
    }

    if (stream.blocked_session(flow, p) || (flow->session_state & STREAM_STATE_IGNORE))
        flow_ready = false;

    // FIXIT-L expected flow should be checked by flow_con before we get here
    // harmonize this with that and the checks above
    char ignore = flow_con->expected_flow(flow, p);
    if (ignore)
    {
        server->flush_policy = STREAM_FLPOLICY_IGNORE;
        client->flush_policy = STREAM_FLPOLICY_IGNORE;
        flow_ready = false;
    }

    return flow_ready;
}

void TcpSession::cleanup_session_if_expired(Packet* p)
{
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
}

bool TcpSession::do_packet_analysis_pre_checks(Packet* p, TcpSegmentDescriptor& tsd)
{
    if ( !is_flow_handling_packets(p) )
        return false;

    // FIXIT - need to do something here to handle check for need to swap trackers??

    if (config == nullptr )
        config = get_tcp_cfg(flow->ssn_server);

    if( !tcp_init )
        set_os_policy( );

    // Check if the session is expired. Should be done before we do something with
    // the packet...Insert a packet, or handle state change SYN, FIN, RST, etc.
    cleanup_session_if_expired(p);

    pkt_action_mask = ACTION_NOTHING;
    tel.clear_tcp_events();
    // process thru state machine...talker first
    if (p->packet_flags & PKT_FROM_CLIENT)
    {
        update_session_on_client_packet(tsd);
        DEBUG_WRAP(t_name = "Server"; l_name = "Client");
    }
    else
    {
        update_session_on_server_packet(tsd);
        DEBUG_WRAP(t_name = "Server"; l_name = "Client");
    }

    update_ignored_session(tsd);
    set_window_scale(*talker, *listener, tsd);
    check_for_session_hijack(tsd);

    DebugFormat(DEBUG_STREAM_STATE, "   %s [talker] state: %s\n", t_name,
        tcp_state_names[talker->get_tcp_state()]);
    DebugFormat(DEBUG_STREAM_STATE, "   %s state: %s(%d)\n", l_name,
        tcp_state_names[listener->get_tcp_state()], listener->get_tcp_state());

    return true;
}

bool TcpSession::validate_packet_established_session(TcpSegmentDescriptor& tsd)
{
    pkt_action_mask |= listener->normalizer->handle_paws(tsd);

    if ( pkt_action_mask & ACTION_BAD_PKT )
        return false;

    return true;
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
        p->ptrs.tcph->seq(), p->ptrs.tcph->ack(), p->dsize);
        );

    TcpSegmentDescriptor tsd(flow, p, tel);
    if ( !do_packet_analysis_pre_checks(p, tsd) )
        return ACTION_NOTHING;

    if ( ( flow->get_session_flags() & SSNFLAG_RESET ) && tsd.get_tcph()->is_syn()
        && !handle_syn_on_reset_session(tsd) )
        return ACTION_NOTHING;
    else
    {
        Profile profile(s5TcpStatePerfStats);

        if ( tsm.eval(tsd, *talker, *listener) )
        {
            do_packet_analysis_post_checks(p);
            S5TraceTCP(p, flow, &tsd, 0);
        }
        else
        {
            if ( pkt_action_mask & ACTION_BAD_PKT )
            {
                DebugMessage(DEBUG_STREAM_STATE, "bad packet, bailing\n");
                inc_tcp_discards();

                do_packet_analysis_post_checks(p);
            }

            tel.log_tcp_events();
            S5TraceTCP(p, flow, &tsd, 0);
        }
    }

    DebugMessage(DEBUG_STREAM_STATE,
        "Finished Stream TCP cleanly!\n---------------------------------------------------\n");

    return ACTION_NOTHING;
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

