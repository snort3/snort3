//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_tracker.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jun 24, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_stream_tracker.h"

#include <daq.h>

#include "main/analyzer.h"
#include "main/snort.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "profiler/profiler_defs.h"
#include "protocols/eth.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"

#include "held_packet_queue.h"
#include "tcp_overlap_resolver.h"
#include "tcp_normalizers.h"
#include "tcp_reassembler.h"
#include "tcp_reassembler_ids.h"
#include "tcp_reassembler_ips.h"
#include "tcp_session.h"

using namespace snort;

THREAD_LOCAL HeldPacketQueue* hpq = nullptr;

const std::list<HeldPacket>::iterator TcpStreamTracker::null_iterator { };

const char* tcp_state_names[] =
{
    "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV",
    "TCP_ESTABLISHED", "TCP_MID_STREAM_SENT", "TCP_MID_STREAM_RECV",
    "TCP_FIN_WAIT1", "TCP_FIN_WAIT2", "TCP_CLOSE_WAIT", "TCP_CLOSING",
    "TCP_LAST_ACK", "TCP_TIME_WAIT", "TCP_CLOSED",
    "TCP_STATE_NONE"
};

const char* tcp_event_names[] = {
    "TCP_SYN_SENT_EVENT", "TCP_SYN_RECV_EVENT",
    "TCP_SYN_ACK_SENT_EVENT", "TCP_SYN_ACK_RECV_EVENT",
    "TCP_ACK_SENT_EVENT", "TCP_ACK_RECV_EVENT",
    "TCP_DATA_SEG_SENT_EVENT", "TCP_DATA_SEG_RECV_EVENT",
    "TCP_FIN_SENT_EVENT", "TCP_FIN_RECV_EVENT",
    "TCP_RST_SENT_EVENT", "TCP_RST_RECV_EVENT"
};

TcpStreamTracker::TcpStreamTracker(bool client) :
    client_tracker(client), tcp_state(client ? TCP_STATE_NONE : TCP_LISTEN),
    held_packet(null_iterator)
{ 
    flush_policy = STREAM_FLPOLICY_IGNORE;
    update_flush_policy(nullptr);
}

TcpStreamTracker::~TcpStreamTracker()
{
    if ( reassembler and (reassembler->get_flush_policy() != STREAM_FLPOLICY_IGNORE) )
    	delete reassembler;

    if( oaitw_reassembler )
    {
        delete oaitw_reassembler;
        oaitw_reassembler = nullptr;
    }

    if ( splitter )
        splitter->go_away();
}

void TcpStreamTracker::reset()
{
    tcp_alerts.clear();
    seglist.reset();
    reassembler->reset_paf();
}

void TcpStreamTracker::clear_tracker(snort::Flow* flow, snort::Packet* p, bool flush_segments, bool restart)
{
    if ( flush_segments )
        reassembler->flush_queued_segments(flow, true, p);

    if ( p )
        finalize_held_packet(p);
    else
        finalize_held_packet(flow);

    seglist.purge_segment_list();

    if ( restart )
        reassembler->reset_paf();
    else
        reassembler->clear_paf();

    set_splitter((StreamSplitter*)nullptr);
}

TcpStreamTracker::TcpEvent TcpStreamTracker::set_tcp_event(const TcpSegmentDescriptor& tsd)
{
    bool talker;
    const tcp::TCPHdr* tcph = tsd.get_tcph();

    if ( tsd.is_packet_from_client() )
        talker = ( client_tracker ) ? true : false;
    else
        talker = ( client_tracker ) ? false : true;

    // FIXIT-P would a lookup table help perf?  the code would be a little cleaner too.
    if ( talker )
    {
        // talker events
        if ( tcph->is_syn_only() )
        {
            tcp_event = TCP_SYN_SENT_EVENT;
            if ( tcp_state == TcpStreamTracker::TCP_STATE_NONE )
                DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_SYN, tsd.get_pkt());
        }
        else if ( tcph->is_syn_ack() )
        {
            tcp_event = TCP_SYN_ACK_SENT_EVENT;
            if ( tcp_state == TcpStreamTracker::TCP_LISTEN )
                DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_SYN_ACK, tsd.get_pkt());
            else if ( tcp_state == TcpStreamTracker::TCP_SYN_RECV )
            {
                Flow* flow = tsd.get_flow();
                if ( flow->get_session_flags() & SSNFLAG_SEEN_CLIENT )
                {
                    TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
                    if ( listener_state == TcpStreamTracker::TCP_SYN_SENT )
                        DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_SYN_ACK, tsd.get_pkt());
                }
            }
        }
        else if ( tcph->is_rst() )
            tcp_event = TCP_RST_SENT_EVENT;
        else if ( tcph->is_fin( ) )
            tcp_event = TCP_FIN_SENT_EVENT;
        else if ( tcph->is_ack() || tcph->is_psh() )
        {
            if ( tsd.is_data_segment() )
                tcp_event = TCP_DATA_SEG_SENT_EVENT;
            else
                tcp_event = TCP_ACK_SENT_EVENT;
        }
        else
        {
            // count no flags set on the talker side...
            tcpStats.no_flags_set++;
            tcp_event = TCP_NO_FLAGS_EVENT;
        }

        (client_tracker) ? session->tcp_ssn_stats.client_events.set(tcp_event) :
            session->tcp_ssn_stats.server_events.set(tcp_event);
    }
    else
    {
        // listener events
        if ( tcph->is_syn_only() )
        {
            tcp_event = TCP_SYN_RECV_EVENT;
            tcpStats.syns++;
        }
        else if ( tcph->is_syn_ack() )
        {
            tcp_event = TCP_SYN_ACK_RECV_EVENT;
            tcpStats.syn_acks++;
        }
        else if ( tcph->is_rst() )
        {
            tcp_event = TCP_RST_RECV_EVENT;
            tcpStats.resets++;
        }
        else if ( tcph->is_fin( ) )
        {
            tcp_event = TCP_FIN_RECV_EVENT;
            tcpStats.fins++;
        }
        else if ( tcph->is_ack() || tcph->is_psh() )
        {
            if ( tsd.is_data_segment() )
                tcp_event = TCP_DATA_SEG_RECV_EVENT;
            else
                tcp_event = TCP_ACK_RECV_EVENT;
        }
        else
        {
            tcp_event = TCP_NO_FLAGS_EVENT;
        }
    }

    return tcp_event;
}

// Use a for loop and byte comparison, which has proven to be faster on pipelined architectures
// compared to a memcmp (setup for memcmp is slow).  Not using a 4 byte and 2 byte long because
// there is no guarantee of memory alignment (and thus performance issues similar to memcmp).
bool TcpStreamTracker::compare_mac_addresses(const uint8_t eth_addr[])
{
    if ( !mac_addr_valid )
        return true;

    for ( int i = 0; i < 6; ++i )
        if ( mac_addr[i] != eth_addr[i] )
            return false;

    return true;
}

void TcpStreamTracker::cache_mac_address(const TcpSegmentDescriptor& tsd, uint8_t direction)
{
    /* Not Ethernet based, nothing to do */
    if ( tsd.get_pkt()->is_eth() )
    {
        // if flag is set, guaranteed to have an eth layer
        const eth::EtherHdr* eh = layer::get_eth_layer(tsd.get_pkt() );

        if ( direction == FROM_CLIENT )
        {
            if ( client_tracker )
                for ( int i = 0; i < 6; i++ )
                    mac_addr[i] = eh->ether_src[i];
            else
                for ( int i = 0; i < 6; i++ )
                    mac_addr[i] = eh->ether_dst[i];
        }
        else
        {
            if ( client_tracker )
                for ( int i = 0; i < 6; i++ )
                    mac_addr[i] = eh->ether_dst[i];
            else
                for ( int i = 0; i < 6; i++ )
                    mac_addr[i] = eh->ether_src[i];
        }

        mac_addr_valid = true;
    }
}

void TcpStreamTracker::set_fin_seq_status_seen(const TcpSegmentDescriptor& tsd)
{
    if ( !fin_seq_set and SEQ_GEQ(tsd.get_end_seq(), r_win_base) )
    {
        fin_i_seq = tsd.get_seq();
        fin_final_seq = tsd.get_end_seq();
        fin_seq_set = true;
        fin_seq_status = FIN_WITH_SEQ_SEEN;
    }
}

void TcpStreamTracker::init_tcp_state(TcpSession* s)
{
    session = s;
    tcp_state = ( client_tracker ) ?
        TcpStreamTracker::TCP_STATE_NONE : TcpStreamTracker::TCP_LISTEN;

    snd_una = snd_nxt = snd_wnd = 0;
    rcv_nxt = r_win_base = iss = irs = 0;
    ts_last = ts_last_packet = 0;
    small_seg_count = 0;
    wscale = 0;
    mss = 0;
    tf_flags = 0;
    mac_addr_valid = false;
    fin_i_seq = 0;
    fin_final_seq = 0;
    fin_seq_status = FIN_NOT_SEEN;
    fin_seq_set = false;
    rst_pkt_sent = false;
    order = TcpStreamTracker::IN_SEQUENCE;
    held_packet = null_iterator;

    flush_policy = STREAM_FLPOLICY_IGNORE;
    update_flush_policy(nullptr);

    seglist.reset();
    tcp_alerts.clear();
}

void TcpStreamTracker::update_stream_order(const TcpSegmentDescriptor& tsd, bool aligned)
{
    uint32_t seq = tsd.get_seq();

    switch ( order )
    {
        case TcpStreamTracker::IN_SEQUENCE:
            if ( aligned )
                tsd.set_packet_flags(PKT_STREAM_ORDER_OK);
            else if ( SEQ_GT(seq, rcv_nxt) )
            {
                order = TcpStreamTracker::NONE;
                hole_left_edge = rcv_nxt;
                hole_right_edge = seq - 1;
            }
            break;

        case TcpStreamTracker::NONE:
            if ( aligned )
            {
                tsd.set_packet_flags(PKT_STREAM_ORDER_OK);
                if ( SEQ_GT(tsd.get_end_seq(), hole_right_edge) )
                    order = TcpStreamTracker::OUT_OF_SEQUENCE;
                else
                    hole_left_edge = tsd.get_end_seq();
            }
            else
            {
                if ( SEQ_LEQ(seq, hole_right_edge) )
                {
                    if ( SEQ_GT(seq, hole_left_edge) )
                        hole_right_edge = seq - 1;
                    else if ( SEQ_GT(tsd.get_end_seq(), hole_left_edge) )
                    {
                        hole_left_edge = tsd.get_end_seq();
                        tsd.set_packet_flags(PKT_STREAM_ORDER_OK);
                    }
                }
                // accounting for overlaps when not aligned
                if ( SEQ_GT(hole_left_edge, hole_right_edge) )
                    order = TcpStreamTracker::OUT_OF_SEQUENCE;
            }
            break;

        case TcpStreamTracker::OUT_OF_SEQUENCE:
            tsd.set_packet_flags(PKT_STREAM_ORDER_BAD);
    }
}

void TcpStreamTracker::update_flush_policy(StreamSplitter* splitter)
{
    if( oaitw_reassembler )
    {
        delete oaitw_reassembler;
        oaitw_reassembler = nullptr;
    }

   if ( reassembler and flush_policy == reassembler->get_flush_policy() )
    {
        reassembler->init(!client_tracker, splitter);
        return;
    }

    if ( flush_policy == STREAM_FLPOLICY_IGNORE )
    {
        // switching to Ignore flush policy...save pointer to current reassembler to delete later
        if ( reassembler )
        {
            seglist.purge_segment_list();
            oaitw_reassembler = reassembler;
        }

        reassembler = TcpReassemblerIgnore::get_instance(!client_tracker);
    }
    else if ( flush_policy == STREAM_FLPOLICY_ON_DATA )
    {
        // update from IDS -> IPS is not supported
        assert( !reassembler or reassembler->get_flush_policy() != STREAM_FLPOLICY_ON_ACK );

        reassembler = new TcpReassemblerIps(*this, seglist);
        reassembler->init(!client_tracker, splitter);
    }
    else
    {
        // update from IPS -> IDS is not supported
        assert( !reassembler or reassembler->get_flush_policy() != STREAM_FLPOLICY_ON_DATA );

        reassembler = new TcpReassemblerIds(*this, seglist);
        reassembler->init(!client_tracker, splitter);
    }
}

void TcpStreamTracker::set_splitter(StreamSplitter* ss)
{
    if ( splitter )
    {
        reassembler->release_splitter();
        splitter->go_away();
    }

    splitter = ss;
    if ( ss )
    {
        if ( normalizer.is_tcp_ips_enabled() )
            flush_policy = STREAM_FLPOLICY_ON_DATA;
        else
            flush_policy = STREAM_FLPOLICY_ON_ACK;
    }
    else
        flush_policy = STREAM_FLPOLICY_IGNORE;

    update_flush_policy(ss);
}

void TcpStreamTracker::set_splitter(const Flow* flow)
{
    Inspector* ins = flow->gadget;

    if ( !ins )
        ins = flow->clouseau;

    if ( ins )
        set_splitter(ins->get_splitter(!client_tracker));
    else
        set_splitter(new AtomSplitter(!client_tracker));
}

static inline bool both_splitters_aborted(Flow* flow)
{
    uint32_t both_splitters_yoinked = (SSNFLAG_ABORT_CLIENT | SSNFLAG_ABORT_SERVER);
    return (flow->get_session_flags() & both_splitters_yoinked) == both_splitters_yoinked;
}

void TcpStreamTracker::fallback()
{
#ifndef NDEBUG
    assert(splitter);

    // FIXIT-L: consolidate these 3
    //bool to_server = splitter->to_server();
    //assert(server_side == to_server && server_side == !tracker.client_tracker);
#endif

    if (PacketTracer::is_active())
        PacketTracer::log("stream_tcp: %s tracker fallback to the Atom splitter.\n",
            client_tracker ? "client" : "server");

    set_splitter(new AtomSplitter(!client_tracker));
    tcpStats.partial_fallbacks++;

    Flow* flow = session->flow;
    if ( !client_tracker )
        flow->set_session_flags(SSNFLAG_ABORT_SERVER);
    else
        flow->set_session_flags(SSNFLAG_ABORT_CLIENT);

    if ( flow->gadget and both_splitters_aborted(flow) )
    {
        flow->clear_gadget();

        if (flow->clouseau)
            flow->clear_clouseau();

        tcpStats.inspector_fallbacks++;
    }
}

void TcpStreamTracker::disable_reassembly(Flow* f)
{
    set_splitter((StreamSplitter*)nullptr);
    seglist.purge_segment_list();
    reassembler->reset_paf();
    finalize_held_packet(f);
}

void TcpStreamTracker::init_on_syn_sent(TcpSegmentDescriptor& tsd)
{
    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_CLIENT);
    if ( tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE) )
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_CLIENT_QUERY);

    iss = tsd.get_seq();
    snd_una = iss;
    snd_nxt = tsd.get_end_seq();
    snd_wnd =  tsd.get_wnd();

    ts_last_packet = tsd.get_packet_timestamp();
    tf_flags |= normalizer.get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_timestamp();
    if (ts_last == 0)
        tf_flags |= TF_TSTAMP_ZERO;
    tf_flags |= tsd.init_mss(&mss);
    tf_flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_CLIENT);
    tcp_state = TcpStreamTracker::TCP_SYN_SENT;
    tcpStats.sessions_on_syn++;
}

void TcpStreamTracker::init_on_syn_recv(const TcpSegmentDescriptor& tsd)
{
    irs = tsd.get_seq();

    rcv_nxt = tsd.get_seq() + 1;
    r_win_base = tsd.get_seq() + 1;
    seglist.set_seglist_base_seq(tsd.get_seq() + 1);

    cache_mac_address(tsd, FROM_CLIENT);
    tcp_state = TcpStreamTracker::TCP_SYN_RECV;
}

void TcpStreamTracker::init_on_synack_sent(TcpSegmentDescriptor& tsd)
{
    tsd.get_flow()->set_session_flags(SSNFLAG_SEEN_SERVER);
    if (tsd.get_tcph()->are_flags_set(TH_CWR | TH_ECE))
        tsd.get_flow()->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

    iss = tsd.get_seq();
    irs = tsd.get_ack() - 1;
    snd_una = tsd.get_seq();
    snd_nxt = tsd.get_end_seq();
    snd_wnd = tsd.get_wnd();

    r_win_base = tsd.get_ack();
    rcv_nxt = tsd.get_ack();
    seglist.set_seglist_base_seq(tsd.get_ack() );

    ts_last_packet = tsd.get_packet_timestamp();
    tf_flags |= normalizer.get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_timestamp();
    if ( ts_last == 0 )
        tf_flags |= TF_TSTAMP_ZERO;
    tf_flags |= tsd.init_mss(&mss);
    tf_flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, FROM_SERVER);
    tcp_state = TcpStreamTracker::TCP_SYN_RECV;
    tcpStats.sessions_on_syn_ack++;
}

void TcpStreamTracker::init_on_synack_recv(const TcpSegmentDescriptor& tsd)
{
    iss = tsd.get_ack() - 1;
    irs = tsd.get_seq();
    snd_una = tsd.get_ack();
    snd_nxt = snd_una;

    rcv_nxt = tsd.get_seq() + 1;
    r_win_base = tsd.get_seq() + 1;
    seglist.set_seglist_base_seq(tsd.get_seq() + 1);

    cache_mac_address(tsd, FROM_SERVER);
    if ( TcpStreamTracker::TCP_SYN_SENT == tcp_state )
        tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
    else
        tcp_state = TcpStreamTracker::TCP_SYN_SENT;
}

void TcpStreamTracker::init_on_data_seg_sent(TcpSegmentDescriptor& tsd)
{
    Flow* flow = tsd.get_flow();

    if ( flow->ssn_state.direction == FROM_CLIENT )
        flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
    else
        flow->set_session_flags(SSNFLAG_SEEN_SERVER);

    iss = tsd.get_seq() - 1;
    irs = tsd.get_ack() - 1;
    snd_una = tsd.get_seq();
    snd_nxt = snd_una + tsd.get_len();
    snd_wnd = tsd.get_wnd();

    r_win_base = tsd.get_ack();
    rcv_nxt = tsd.get_ack();
    seglist.set_seglist_base_seq(tsd.get_ack());

    ts_last_packet = tsd.get_packet_timestamp();
    tf_flags |= normalizer.get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_timestamp();
    if (ts_last == 0)
        tf_flags |= TF_TSTAMP_ZERO;
    tf_flags |= tsd.init_wscale(&wscale);

    cache_mac_address(tsd, tsd.get_direction() );
    tcp_state = TcpStreamTracker::TCP_MID_STREAM_SENT;
}

void TcpStreamTracker::init_on_data_seg_recv(const TcpSegmentDescriptor& tsd)
{
    iss = tsd.get_ack() - 1;
    irs = tsd.get_seq() - 1;
    snd_una = tsd.get_ack();
    snd_nxt = snd_una;
    snd_wnd = 0; /* reset later */

    rcv_nxt = tsd.get_seq();
    r_win_base = tsd.get_seq();
    seglist.set_seglist_base_seq(tsd.get_seq());

    cache_mac_address(tsd, tsd.get_direction() );
    tcpStats.sessions_on_data++;
    tcp_state = TcpStreamTracker::TCP_MID_STREAM_RECV;
}

void TcpStreamTracker::finish_server_init(TcpSegmentDescriptor& tsd)
{
    iss = tsd.get_seq();
    snd_una = tsd.get_seq();
    snd_nxt = tsd.get_end_seq();
    snd_wnd = tsd.get_wnd();

    // FIXIT-M move this to fin handler for syn_recv state ..
    //if ( tcph->is_fin() )
    //    server->set_snd_nxt(server->get_snd_nxt() - 1);

    tf_flags |= normalizer.get_tcp_timestamp(tsd, false);
    ts_last = tsd.get_timestamp();
    if ( ts_last != 0 )
        ts_last_packet = tsd.get_packet_timestamp();
    else
        tf_flags |= TF_TSTAMP_ZERO;

    tf_flags |= ( tsd.init_mss(&mss) | tsd.init_wscale(&wscale) );
}

void TcpStreamTracker::finish_client_init(const TcpSegmentDescriptor& tsd)
{
    Flow* flow = tsd.get_flow();
    rcv_nxt = tsd.get_end_seq();

    if ( seglist.data_was_queued() )
        return;  // we already have state, don't mess it up

    if ( !Stream::is_midstream(flow) )
    {
        if ( tsd.get_tcph()->is_syn() )
            seglist.set_seglist_base_seq(tsd.get_seq() + 1);
        else
            seglist.set_seglist_base_seq(tsd.get_seq());

        r_win_base = tsd.get_end_seq();
    }
    else
    {
        seglist.set_seglist_base_seq(tsd.get_seq());
        r_win_base = tsd.get_seq();
    }
}

void TcpStreamTracker::update_tracker_ack_recv(TcpSegmentDescriptor& tsd)
{
    if ( SEQ_GT(tsd.get_ack(), snd_una) )
    {
        snd_una = tsd.get_ack();
        if ( SEQ_LT(snd_nxt, snd_una) )
            snd_nxt = snd_una;
    }
    if ( !tsd.get_len() and SEQ_LT(tsd.get_seq(), r_win_base) )
    {
        if ( snd_wnd == 0 )
            tcpStats.zero_win_probes++;
        else if ( (r_win_base - tsd.get_seq()) == MAX_KEEP_ALIVE_PROBE_LEN
            and !(tsd.get_tcph()->th_flags & (TH_SYN|TH_FIN|TH_RST)) )
            tcpStats.keep_alive_probes++;
    }
}

// In no-ack policy, data is implicitly acked immediately.
void TcpStreamTracker::update_tracker_no_ack_recv(const TcpSegmentDescriptor& tsd)
{
    snd_una = snd_nxt = tsd.get_end_seq();
}

void TcpStreamTracker::update_tracker_no_ack_sent(const TcpSegmentDescriptor& tsd)
{
    r_win_base = tsd.get_end_seq();
    reassembler->eval_flush_policy_on_ack(tsd.get_pkt());
}

void TcpStreamTracker::update_tracker_ack_sent(TcpSegmentDescriptor& tsd)
{
    if ( SEQ_GT(tsd.get_end_seq(), snd_nxt) )
        snd_nxt = tsd.get_end_seq();

    if ( SEQ_GEQ(tsd.get_ack(), r_win_base) )
    {
        if ( SEQ_GT(tsd.get_ack(), r_win_base) )
            r_win_base = tsd.get_ack();

        snd_wnd = tsd.get_wnd();
    }

    if ( flush_policy == STREAM_FLPOLICY_IGNORE
        and SEQ_GT(tsd.get_ack(), rcv_nxt) )
        rcv_nxt = tsd.get_ack();

    if ( ( fin_seq_status == FIN_WITH_SEQ_SEEN )
        && SEQ_GEQ(tsd.get_ack(), fin_final_seq + 1) && !(tsd.is_meta_ack_packet()) )
    {
        fin_seq_status = FIN_WITH_SEQ_ACKED;
    }

    reassembler->eval_flush_policy_on_ack(tsd.get_pkt());
}

bool TcpStreamTracker::update_on_3whs_ack(TcpSegmentDescriptor& tsd)
{
    bool good_ack = is_ack_valid(tsd.get_ack());

    if ( good_ack )
    {
        if (!irs)  // FIXIT-L zero is a valid seq# so this kind of check is incorrect
            irs = tsd.get_seq();
        finish_client_init(tsd);
        update_tracker_ack_recv(tsd);
        TcpStreamTracker::TcpState talker_state = tsd.get_talker()->get_tcp_state();
        if ( TcpStreamTracker::TCP_ESTABLISHED == talker_state )
            session->set_established(tsd);
        tcp_state = TcpStreamTracker::TCP_ESTABLISHED;
    }

    return good_ack;
}

bool TcpStreamTracker::update_on_rst_recv(TcpSegmentDescriptor& tsd)
{
    normalizer.trim_rst_payload(tsd);
    bool good_rst = normalizer.validate_rst(tsd);
    if ( good_rst )
    {
        Flow* flow = tsd.get_flow();

        flow->set_session_flags(SSNFLAG_RESET);
        if ( normalizer.is_tcp_ips_enabled() )
            tcp_state = TcpStreamTracker::TCP_CLOSED;
    }
    else
    {
        session->tel.set_tcp_event(EVENT_BAD_RST);
        normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
        session->set_pkt_action_flag(ACTION_BAD_PKT);
    }

    return good_rst;
}

void TcpStreamTracker::update_on_rst_sent()
{
    tcp_state = TcpStreamTracker::TCP_CLOSED;
    rst_pkt_sent = true;
}

bool TcpStreamTracker::update_on_fin_recv(TcpSegmentDescriptor& tsd)
{
    if ( session->flow->two_way_traffic() )
    {
        if ( SEQ_LT(tsd.get_end_seq(), r_win_base) )
            return false;

        //--------------------------------------------------
        // FIXIT-L don't bump rcv_nxt unless FIN is in seq
        // because it causes bogus 129:5 cases
        // but doing so causes extra gaps
        if ( SEQ_EQ(tsd.get_end_seq(), rcv_nxt) )
            rcv_nxt++;
        else
            fin_seq_adjust = 1;
    }
    else
        rcv_nxt++;

    return true;
}

bool TcpStreamTracker::update_on_fin_sent(TcpSegmentDescriptor& tsd)
{
    update_tracker_ack_sent(tsd);
    snd_nxt++;
    return true;
}

bool TcpStreamTracker::is_segment_seq_valid(TcpSegmentDescriptor& tsd)
{
    bool valid_seq = true;

    int right_ok;
    uint32_t left_seq;

    if ( SEQ_LT(rcv_nxt, r_win_base) )
        left_seq = rcv_nxt;
    else
        left_seq = r_win_base;

    if ( tsd.is_data_segment() )
        right_ok = SEQ_GT(tsd.get_end_seq(), left_seq);
    else
        right_ok = SEQ_GEQ(tsd.get_end_seq(), left_seq);

    if ( right_ok )
    {
        uint32_t win = normalizer.get_stream_window(tsd);

        if ( SEQ_LEQ(tsd.get_seq(), r_win_base + win) )
            return true;
        else
            valid_seq = false;
    }
    else
        valid_seq = false;

    return valid_seq;
}

bool TcpStreamTracker::set_held_packet(Packet* p)
{
    if ( held_packet != null_iterator )
        return false;

    held_packet = hpq->append(p->daq_msg, p->ptrs.tcph->seq(), *this);
    held_pkt_seq = p->ptrs.tcph->seq();

    tcpStats.total_packets_held++;
    if ( ++tcpStats.current_packets_held > tcpStats.max_packets_held )
        tcpStats.max_packets_held = tcpStats.current_packets_held;

    return true;
}

int32_t TcpStreamTracker::kickstart_asymmetric_flow(const TcpSegmentDescriptor& tsd, uint32_t max_queued_bytes)
{
    seglist.skip_holes();

    if ( reassembler->is_splitter_paf() )
        fallback();
    else
        reassembler->reset_paf();

    reassembler->eval_asymmetric_flush(tsd.get_pkt());

    int32_t space_left = max_queued_bytes - seglist.get_seg_bytes_total();

    if ( get_tcp_state() == TcpStreamTracker::TCP_MID_STREAM_RECV )
    {
        set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        if (PacketTracer::is_active())
            PacketTracer::log("stream_tcp: Kickstart of midstream asymmetric flow! Seglist queue space: %u\n",
                space_left );
    }
    else
    {
        if (PacketTracer::is_active())
            PacketTracer::log("stream_tcp: Kickstart of asymmetric flow! Seglist queue space: %u\n",
                space_left );
    }

    return space_left;
}

void TcpStreamTracker::perform_fin_recv_flush(TcpSegmentDescriptor& tsd)
{
    if ( tsd.is_data_segment() )
        session->handle_data_segment(tsd);

    Packet* p = tsd.get_pkt();
    if ( flush_policy == STREAM_FLPOLICY_ON_DATA and SEQ_EQ(tsd.get_end_seq(), rcv_nxt)
         and !p->flow->searching_for_service() )
        reassembler->finish_and_final_flush(p->flow, true, p);
    else if ( !p->flow->two_way_traffic() )
        reassembler->eval_asymmetric_flush(p);
}

uint32_t TcpStreamTracker::perform_partial_flush()
{
    uint32_t flushed = 0;
    if ( held_packet != null_iterator )
    {
        Packet* p;
        flushed = reassembler->perform_partial_flush(session->flow, p);

        // If the held_packet hasn't been released by perform_partial_flush(),
        // call finalize directly.
        if ( is_holding_packet() )
        {
            finalize_held_packet(p);
            tcpStats.held_packet_purges++;
        }

        // call this here explicitly, because we've avoided it in reassembler
        // and we need to set flow state to BLOCK, if need be
        Stream::check_flow_closed(p);
    }
    return flushed;
}

bool TcpStreamTracker::is_retransmit_of_held_packet(Packet* cp)
{
    if ( (held_packet == null_iterator) or ( cp->daq_msg == held_packet->get_daq_msg() ) )
        return false;

    uint32_t next_send_seq = cp->ptrs.tcph->seq() + (uint32_t)cp->dsize;
    if ( SEQ_LEQ(cp->ptrs.tcph->seq(), held_packet->get_seq_num()) and SEQ_GT(next_send_seq, held_packet->get_seq_num()) )
    {
        tcpStats.held_packet_rexmits++;
        return true;
    }

    return false;
}

void TcpStreamTracker::finalize_held_packet(Packet* cp)
{
    if ( held_packet != null_iterator )
    {
        DAQ_Msg_h msg = held_packet->get_daq_msg();

        if ( cp->active->packet_was_dropped() )
        {
            DAQ_Verdict verdict = held_packet->has_expired() ? DAQ_VERDICT_BLACKLIST : DAQ_VERDICT_BLOCK;
            Analyzer::get_local_analyzer()->finalize_daq_message(msg, verdict);
            tcpStats.held_packets_dropped++;
        }
        else
        {
            if ( cp->active->packet_retry_requested() )
            {
                tcpStats.held_packet_retries++;
                Analyzer::get_local_analyzer()->add_to_retry_queue(msg, cp->flow);
            }
            else
            {
                Analyzer::get_local_analyzer()->finalize_daq_message(msg, DAQ_VERDICT_PASS);
                tcpStats.held_packets_passed++;
            }

            TcpSession* tcp_session = (TcpSession*)cp->flow->session;
            tcp_session->held_packet_dir = SSN_DIR_NONE;
        }

        hpq->erase(held_packet);
        held_packet = null_iterator;
        tcpStats.current_packets_held--;
    }

    if (cp->active->is_packet_held())
        cp->active->cancel_packet_hold();
}

void TcpStreamTracker::finalize_held_packet(Flow* flow)
{
    if ( held_packet != null_iterator )
    {
        DAQ_Msg_h msg = held_packet->get_daq_msg();

        if ( (flow->session_state & STREAM_STATE_BLOCK_PENDING) ||
             (flow->ssn_state.session_flags & SSNFLAG_BLOCK) )
        {
            DAQ_Verdict verdict = held_packet->has_expired() ? DAQ_VERDICT_BLACKLIST : DAQ_VERDICT_BLOCK;
            Analyzer::get_local_analyzer()->finalize_daq_message(msg, verdict);
            tcpStats.held_packets_dropped++;
        }
        else
        {
            TcpSession* tcp_session = (TcpSession*)flow->session;
            tcp_session->held_packet_dir = SSN_DIR_NONE;
            Analyzer::get_local_analyzer()->finalize_daq_message(msg, DAQ_VERDICT_PASS);
            tcpStats.held_packets_passed++;
        }

        hpq->erase(held_packet);
        held_packet = null_iterator;
        tcpStats.current_packets_held--;
    }
}

bool TcpStreamTracker::release_held_packets(const timeval& cur_time, int max_remove)
{
    bool is_front_expired = false;
    if ( hpq )
        is_front_expired = hpq->execute(cur_time, max_remove);
    return is_front_expired;
}

void TcpStreamTracker::set_held_packet_timeout(const uint32_t ms)
{
    assert(hpq);
    hpq->set_timeout(ms);
}

bool TcpStreamTracker::adjust_expiration(uint32_t new_timeout_ms, const timeval& now)
{
    assert(hpq);
    return hpq->adjust_expiration(new_timeout_ms, now);
}

void TcpStreamTracker::thread_init()
{
    assert(!hpq);
    hpq = new HeldPacketQueue();

    TcpReassembler::tinit();
}

void TcpStreamTracker::thread_term()
{
    assert(hpq->empty());
    delete hpq;
    hpq = nullptr;

    TcpReassembler::tterm();
}
