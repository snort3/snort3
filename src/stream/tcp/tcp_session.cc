//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "tcp_session.h"

#include "detection/detection_engine.h"
#include "detection/rules.h"
#include "log/log.h"
#include "profiler/profiler.h"
#include "protocols/eth.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "packet_tracer/packet_tracer.h"

#include "stream_tcp.h"
#include "tcp_ha.h"
#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_reassemblers.h"
#include "tcp_segment_node.h"
#include "tcp_state_machine.h"
#include "tcp_trace.h"

using namespace snort;

void TcpSession::sinit()
{
    TcpSegmentDescriptor::setup();
    TcpSegmentNode::setup();
}

void TcpSession::sterm()
{
    TcpSegmentDescriptor::clear();
    TcpSegmentNode::clear();
}

TcpSession::TcpSession(Flow* f) : TcpStreamSession(f)
{
    tsm = TcpStateMachine::get_instance();
    splitter_init = false;

    client.session = this;
    server.session = this;
    tcpStats.instantiated++;
}

TcpSession::~TcpSession()
{
    clear_session(true, false, false);
}

bool TcpSession::setup(Packet*)
{
    client.init_tcp_state();
    server.init_tcp_state();
    lws_init = tcp_init = false;
    generate_3whs_alert = true;
    cleaning = false;
    splitter_init = false;

    initiator_watermark = 0;
    pkt_action_mask = ACTION_NOTHING;
    ecn = 0;
    ingress_index = egress_index = 0;
    ingress_group = egress_group = 0;
    daq_flags = address_space_id = 0;

    tcp_config = get_tcp_cfg(flow->ssn_server);
    flow->set_default_session_timeout(tcp_config->session_timeout, false);
    flow->set_idle_timeout(tcp_config->embryonic_timeout);
    set_os_policy();

    SESSION_STATS_ADD(tcpStats)
    tcpStats.setups++;
    return true;
}

// FIXIT-M once TcpReassembler interface is abstract class move this to base class
void TcpSession::restart(Packet* p)
{
    // sanity check since this is called externally
    assert(p);
    assert(p->ptrs.tcph);
    assert(p->flow == flow);

    DetectionEngine::onload(flow);
    TcpStreamTracker* talker;
    TcpStreamTracker* listener;

    if (p->is_from_server())
    {
        talker = &server;
        listener = &client;

        if ( server.get_splitter()->sync_on_start() )
            flush_tracker(server, p, PKT_FROM_CLIENT, false);
    }
    else
    {
        talker = &client;
        listener = &server;
    }

    if ( talker->midstream_initial_ack_flush )
    {
        talker->midstream_initial_ack_flush = false;
        talker->reassembler.flush_on_data_policy(p);
    }

    if (p->dsize > 0)
        listener->reassembler.flush_on_data_policy(p);

    if (p->ptrs.tcph->is_ack())
        talker->reassembler.flush_on_ack_policy(p);

    tcpStats.restarts++;
}

// if the flush_segments parameter is true and clear_session is being called while not in
// the context of a wire packet then the caller must create a packet context by calling
// DetectionEngine::set_next_packet() before calling clear_session
void TcpSession::clear_session(bool free_flow_data, bool flush_segments, bool restart, Packet* p)
{
    assert(!p or p->flow == flow);
    if ( !tcp_init )
    {
        if ( lws_init )
            tcpStats.no_pickups++;
        return;
    }

    lws_init = false;
    tcp_init = false;
    tcpStats.released++;

    if ( flush_segments )
    {
        client.reassembler.flush_queued_segments(flow, true, p);
        server.reassembler.flush_queued_segments(flow, true, p);
    }

    if ( p )
    {
        client.finalize_held_packet(p);
        server.finalize_held_packet(p);
    }
    else
    {
        client.finalize_held_packet(flow);
        server.finalize_held_packet(flow);
    }

    client.reassembler.purge_segment_list();
    server.reassembler.purge_segment_list();

    update_perf_base_state(TcpStreamTracker::TCP_CLOSED);

    set_splitter(true, nullptr);
    set_splitter(false, nullptr);

    if ( restart )
    {
        flow->restart(free_flow_data);
        client.reassembler.reset_paf();
        server.reassembler.reset_paf();
    }
    else
    {
        flow->clear(free_flow_data);
        client.reassembler.clear_paf();
        server.reassembler.clear_paf();
    }

    tel.log_internal_event(SESSION_EVENT_CLEAR);
}

void TcpSession::update_perf_base_state(char newState)
{
    uint32_t session_flags = flow->get_session_flags();
    bool fire_event = false;

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
            session_flags |= SSNFLAG_COUNTED_ESTABLISH;
            fire_event = true;

            tel.log_internal_event(SESSION_EVENT_SETUP);
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
            }
            else if ( session_flags & SSNFLAG_COUNTED_INITIALIZE )
            {
                assert(tcpStats.sessions_initializing);
                tcpStats.sessions_initializing--;
            }
        }
        break;

    case TcpStreamTracker::TCP_CLOSED:
        if ( !( session_flags & SSNFLAG_COUNTED_CLOSED ) )
        {
            session_flags |= SSNFLAG_COUNTED_CLOSED;
            fire_event = true;

            if ( session_flags & SSNFLAG_COUNTED_CLOSING )
            {
                assert(tcpStats.sessions_closing);
                tcpStats.sessions_closing--;
            }
            else if ( session_flags & SSNFLAG_COUNTED_ESTABLISH )
            {
                assert(tcpStats.sessions_established);
                tcpStats.sessions_established--;
            }
            else if ( session_flags & SSNFLAG_COUNTED_INITIALIZE )
            {
                assert(tcpStats.sessions_initializing);
                tcpStats.sessions_initializing--;
            }
        }
        break;

    default:
        break;
    }

    flow->update_session_flags(session_flags);

    if ( fire_event )
        DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_STATE_CHANGE, nullptr, flow);
}

bool TcpSession::flow_exceeds_config_thresholds(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();

    if ( listener->get_flush_policy() == STREAM_FLPOLICY_IGNORE )
        return true;

    // FIXIT-M any discards must be counted and in many cases alerted as well
    // (count all but alert at most once per flow)
    // three cases in this function; look for others
    if ( ( tcp_config->flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY ) && !flow->two_way_traffic() )
        return true;

    if ( tcp_config->max_consec_small_segs )
    {
        if ( tsd.get_len() >= tcp_config->max_consec_small_seg_size )
            listener->small_seg_count = 0;

        else if ( ++listener->small_seg_count == tcp_config->max_consec_small_segs )
            tel.set_tcp_event(EVENT_MAX_SMALL_SEGS_EXCEEDED);
    }

    if ( tcp_config->max_queued_bytes )
    {
        int32_t space_left =
            tcp_config->max_queued_bytes - listener->reassembler.get_seg_bytes_total();

        if ( space_left < (int32_t)tsd.get_len() )
        {
            tcpStats.exceeded_max_bytes++;
            bool inline_mode = tsd.is_nap_policy_inline();
            bool ret_val = true;

            if ( space_left > 0 )
                ret_val = !inline_mode; // For partial trim, reassemble only if we can force an inject
            else
                space_left = 0;

            if ( inline_mode )
            {
                if ( listener->max_queue_exceeded == MQ_NONE )
                {
                    listener->max_queue_seq_nxt = tsd.get_seq() + space_left;
                    listener->max_queue_exceeded = MQ_BYTES;
                }
                else
                    (const_cast<tcp::TCPHdr*>(tsd.get_pkt()->ptrs.tcph))->set_seq(listener->max_queue_seq_nxt);
            }

            if( listener->reassembler.segment_within_seglist_window(tsd) )
                return false;

            if ( inline_mode || listener->normalizer.get_trim_win() == NORM_MODE_ON)
            {
                tel.set_tcp_event(EVENT_MAX_QUEUED_BYTES_EXCEEDED);
                listener->normalizer.log_drop_reason(tsd, inline_mode, "stream", 
                "Stream: Flow exceeded the configured max byte threshold (" + std::to_string(tcp_config->max_queued_bytes) +
                "). You may want to adjust the 'max_bytes' parameter in the NAP policy" 
                " to a higher value, or '0' for unlimited.\n");
            }

            listener->normalizer.trim_win_payload(tsd, space_left, inline_mode);
            return ret_val;
        }
        else if ( listener->max_queue_exceeded == MQ_BYTES )
            listener->max_queue_exceeded = MQ_NONE;
    }

    if ( tcp_config->max_queued_segs )
    {
        if ( listener->reassembler.get_seg_count() + 1 > tcp_config->max_queued_segs )
        {
            tcpStats.exceeded_max_segs++;
            bool inline_mode = tsd.is_nap_policy_inline();

            if ( inline_mode )
            {
                if ( listener->max_queue_exceeded == MQ_NONE )
                {
                    listener->max_queue_seq_nxt = tsd.get_seq();
                    listener->max_queue_exceeded = MQ_SEGS;
                }
                else
                    (const_cast<tcp::TCPHdr*>(tsd.get_pkt()->ptrs.tcph))->set_seq(listener->max_queue_seq_nxt);
            }

            if( listener->reassembler.segment_within_seglist_window(tsd) )
                return false;

            if ( inline_mode || listener->normalizer.get_trim_win() == NORM_MODE_ON)
            {
                tel.set_tcp_event(EVENT_MAX_QUEUED_SEGS_EXCEEDED);
                listener->normalizer.log_drop_reason(tsd, inline_mode, "stream",
                "Stream: Flow exceeded the configured max segment threshold (" + std::to_string(tcp_config->max_queued_segs) + 
                "). You may want to adjust the 'max_segments' parameter in the NAP policy" 
                " to a higher value, or '0' for unlimited.\n");
            }

            listener->normalizer.trim_win_payload(tsd, 0, inline_mode);
            return true;
        }
        else if ( listener->max_queue_exceeded == MQ_SEGS )
            listener->max_queue_exceeded = MQ_NONE;
    }

    return false;
}

void TcpSession::update_stream_order(const TcpSegmentDescriptor& tsd, bool aligned)
{
    TcpStreamTracker* listener = tsd.get_listener();
    uint32_t seq = tsd.get_seq();

    switch ( listener->order )
    {
        case TcpStreamTracker::IN_SEQUENCE:
            if ( aligned )
                tsd.set_packet_flags(PKT_STREAM_ORDER_OK);
            else if ( SEQ_GT(seq, listener->rcv_nxt) )
            {
                listener->order = TcpStreamTracker::NONE;
			    listener->hole_left_edge = listener->rcv_nxt;
			    listener->hole_right_edge = seq - 1;
            }
            break;

        case TcpStreamTracker::NONE:
            if ( aligned )
            {
                tsd.set_packet_flags(PKT_STREAM_ORDER_OK);
                if ( SEQ_GT(tsd.get_end_seq(), listener->hole_right_edge) )
			        listener->order = TcpStreamTracker::OUT_OF_SEQUENCE;
			    else
			        listener->hole_left_edge = tsd.get_end_seq();
            }
            else
            {
                if ( SEQ_LEQ(seq, listener->hole_right_edge) )
			    {
			    	if ( SEQ_GT(seq, listener->hole_left_edge) )
			       	    listener->hole_right_edge = seq - 1;
                    else if ( SEQ_GT(tsd.get_end_seq(), listener->hole_left_edge) )
                    {
                        listener->hole_left_edge = tsd.get_end_seq();
                        tsd.set_packet_flags(PKT_STREAM_ORDER_OK);
                    }
			    }
                // accounting for overlaps when not aligned
                if ( SEQ_GT(listener->hole_left_edge, listener->hole_right_edge) )
                    listener->order = TcpStreamTracker::OUT_OF_SEQUENCE;
            }
            break;

        case TcpStreamTracker::OUT_OF_SEQUENCE:
            tsd.set_packet_flags(PKT_STREAM_ORDER_BAD);
    }
}

void TcpSession::set_os_policy()
{
    StreamPolicy client_os_policy = flow->ssn_policy ?
        static_cast<StreamPolicy>( flow->ssn_policy ) : tcp_config->policy;

    StreamPolicy server_os_policy = flow->ssn_policy ?
        static_cast<StreamPolicy>( flow->ssn_policy ) : tcp_config->policy;

    client.normalizer.init(client_os_policy, this, &client, &server);
    server.normalizer.init(server_os_policy, this, &server, &client);

    client.reassembler.init(this, &client, client_os_policy, false);
    server.reassembler.init(this, &server, server_os_policy, true);
}

// FIXIT-M this is no longer called (but should be)
#if 0
void TcpSession::swap_trackers()
{
    uint32_t session_flags = flow->get_session_flags( );
    if ( ( session_flags & SSNFLAG_CLIENT_SWAP ) && !( session_flags & SSNFLAG_CLIENT_SWAPPED ) )
    {
        TcpStreamTracker& trk = client;
        client = server;
        server = trk;

        SfIp ip = flow->client_ip;
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
#endif

void TcpSession::init_session_on_syn(TcpSegmentDescriptor& tsd)
{
    server.init_on_syn_recv(tsd);
    client.init_on_syn_sent(tsd);
    init_new_tcp_session(tsd);
    tcpStats.sessions_on_syn++;
}

void TcpSession::init_session_on_synack(TcpSegmentDescriptor& tsd)
{
    server.init_on_synack_sent(tsd);
    client.init_on_synack_recv(tsd);
    init_new_tcp_session(tsd);
    tcpStats.sessions_on_syn_ack++;
}

void TcpSession::update_timestamp_tracking(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();
    TcpStreamTracker* talker = tsd.get_talker();

    talker->set_tf_flags(listener->normalizer.get_timestamp_flags());
    if (listener->normalizer.handling_timestamps()
        && SEQ_EQ(listener->rcv_nxt, tsd.get_seq()))
    {
        talker->set_ts_last_packet(tsd.get_packet_timestamp());
        talker->set_ts_last(tsd.get_timestamp());
    }
}

bool TcpSession::handle_syn_on_reset_session(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();
    TcpStreamTracker* talker = tsd.get_talker();
    const tcp::TCPHdr* tcph = tsd.get_tcph();

    if ( (listener->get_tcp_state() == TcpStreamTracker::TCP_CLOSED)
         || (talker->get_tcp_state() == TcpStreamTracker::TCP_CLOSED) )
    {
        // Listener previously issued a reset Talker is re-SYN-ing

        // FIXIT-M this leads to bogus 129:20
        clear_session( true, true, true, tsd.get_pkt() );

        if ( tcph->is_rst() )
        {
            // FIXIT-M  In inline mode, only one of the normalizations can
            // occur.  If the first normalization fires, there is nothing
            // for the second normalization to do.  However, in inline-test
            // mode, since nothing is actually normalized, both of the
            // following functions report that they 'would' normalize.
            // i.e., both functions increment their count even though only
            // one function can ever perform a normalization.

            /* Got SYN/RST.  We're done. */
            listener->normalizer.trim_syn_payload(tsd);
            listener->normalizer.trim_rst_payload(tsd);
            set_pkt_action_flag(ACTION_RST);
            return false;
        }
        else if ( tcph->is_syn_only() )
        {
            flow->ssn_state.direction = FROM_CLIENT;
            flow->set_ttl(tsd.get_pkt(), true);
            init_session_on_syn(tsd);
            tcpStats.resyns++;
            listener->normalizer.ecn_tracker(tcph, tcp_config->require_3whs());
            flow->update_session_flags(SSNFLAG_SEEN_CLIENT);
        }
        else if ( tcph->is_syn_ack() )
        {
            if ( tcp_config->midstream_allowed(tsd.get_pkt()) )
            {
                flow->ssn_state.direction = FROM_SERVER;
                flow->set_ttl(tsd.get_pkt(), false);
                init_session_on_synack(tsd);
                tcpStats.resyns++;
            }

            listener->normalizer.ecn_tracker(tcph, tcp_config->require_3whs());
            flow->update_session_flags(SSNFLAG_SEEN_SERVER);
        }
    }

    return true;
}

void TcpSession::update_ignored_session(TcpSegmentDescriptor& tsd)
{
    if ( tsd.is_meta_ack_packet() )
        return;

    Packet* p = tsd.get_pkt();
    // FIXIT-L why flush here instead of just purge?
    // s5_ignored_session() may be disabling detection too soon if we really want to flush
    if ( Stream::ignored_flow(flow, p) )
    {
        TcpStreamTracker* listener = tsd.get_listener();
        TcpStreamTracker* talker = tsd.get_talker();

        if ( talker && ( talker->get_tf_flags() & TF_FORCE_FLUSH ) )
        {
            flush_talker(p);
            talker->clear_tf_flags(TF_FORCE_FLUSH);
        }

        if ( listener && ( listener->get_tf_flags() & TF_FORCE_FLUSH ) )
        {
            flush_listener(p);
            listener->clear_tf_flags(TF_FORCE_FLUSH);
        }

        tsd.set_packet_flags(PKT_IGNORE);
        set_pkt_action_flag(ACTION_DISABLE_INSPECTION);
        tcpStats.ignored++;
    }
}

void TcpSession::handle_data_on_syn(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();

    if ( !listener->normalizer.trim_syn_payload(tsd) )
    {
        handle_data_segment(tsd);
        tel.set_tcp_event(EVENT_DATA_ON_SYN);
    }
}

void TcpSession::update_session_on_rst(TcpSegmentDescriptor& tsd, bool flush)
{
    Packet* p = tsd.get_pkt();

    if ( flush )
    {
        flush_listener(p, true);
        flush_talker(p, true);
        set_splitter(true, nullptr);
        set_splitter(false, nullptr);
    }

    tsd.get_talker()->update_on_rst_sent();
}

void TcpSession::update_paws_timestamps(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();
    TcpStreamTracker* talker = tsd.get_talker();

    if ( no_ack_mode_enabled() )
    {
        talker->set_ts_last(0);
    }
    else if ( listener->normalizer.handling_timestamps()
        && SEQ_EQ(listener->r_win_base, tsd.get_seq()) )
    {
        if ( ((int32_t)(tsd.get_timestamp() - talker->get_ts_last()) >= 0  )
            || (tsd.get_packet_timestamp() >= talker->get_ts_last_packet() + PAWS_24DAYS) )
        {
            talker->set_ts_last(tsd.get_timestamp());
            talker->set_ts_last_packet(tsd.get_packet_timestamp());
        }
    }
}

void TcpSession::check_for_session_hijack(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();
    TcpStreamTracker* talker = tsd.get_talker();

    Packet* p = tsd.get_pkt();
    if ( !(p->pkth->flags & DAQ_PKT_FLAG_PRE_ROUTING) )
    {
        if ( p->is_eth() )
        {
            const eth::EtherHdr* eh = layer::get_eth_layer(p);
            bool t_hijack = !talker->compare_mac_addresses(eh->ether_src);
            bool l_hijack = !listener->compare_mac_addresses(eh->ether_dst);

            // if both seem hijacked then swap src/dst check, it that matches probably a tap
            if ( (t_hijack & l_hijack) && (talker->compare_mac_addresses(eh->ether_dst) &&
                 listener->compare_mac_addresses(eh->ether_src)) )
                return;

            uint32_t event_code = 0;

            if ( t_hijack )
            {
                if ( p->is_from_client() )
                    event_code |= EVENT_SESSION_HIJACK_CLIENT;
                else
                    event_code |= EVENT_SESSION_HIJACK_SERVER;
            }

            if ( l_hijack )
            {
                if ( p->is_from_client() )
                    event_code |= EVENT_SESSION_HIJACK_SERVER;
                else
                    event_code |= EVENT_SESSION_HIJACK_CLIENT;
            }

            if ( event_code )
                tel.set_tcp_event(event_code);
        }
    }
}

bool TcpSession::check_for_window_slam(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();

    if ( tcp_config->max_window && (tsd.get_wnd() > tcp_config->max_window) )
    {
        /* got a window too large, alert! */
        tel.set_tcp_event(EVENT_WINDOW_TOO_LARGE);
        listener->normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
        set_pkt_action_flag(ACTION_BAD_PKT);
        return true;
    }
    else if ( tsd.is_packet_from_client() && (tsd.get_wnd() <= SLAM_MAX)
        && (tsd.get_ack() == listener->get_iss() + 1)
        && !(tsd.get_tcph()->is_fin() || tsd.get_tcph()->is_rst())
        && !(flow->get_session_flags() & SSNFLAG_MIDSTREAM))
    {
        /* got a window slam alert! */
        tel.set_tcp_event(EVENT_WINDOW_SLAM);
        listener->normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
        set_pkt_action_flag(ACTION_BAD_PKT);
        return true;
    }

    return false;
}

void TcpSession::mark_packet_for_drop(TcpSegmentDescriptor& tsd)
{
    tsd.get_listener()->normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
    set_pkt_action_flag(ACTION_BAD_PKT);
}

void TcpSession::handle_data_segment(TcpSegmentDescriptor& tsd, bool flush)
{
    TcpStreamTracker* listener = tsd.get_listener();
    TcpStreamTracker* talker = tsd.get_talker();

    if ( TcpStreamTracker::TCP_CLOSED != talker->get_tcp_state() )
    {
        uint8_t tcp_options_len = tsd.get_tcph()->options_len();
        if ( tsd.is_packet_from_client() )
            client.set_tcp_options_len(tcp_options_len);
        else
            server.set_tcp_options_len(tcp_options_len);

        uint32_t seq = tsd.get_tcph()->is_syn() ? tsd.get_seq() + 1 : tsd.get_seq();
        bool stream_is_inorder = ( seq == listener->rcv_nxt );

        int rc =  listener->normalizer.apply_normalizations(tsd, seq, stream_is_inorder);
        switch ( rc )
        {
        case TcpNormalizer::NORM_OK:
            if ( stream_is_inorder )
                listener->rcv_nxt = tsd.get_end_seq();

            update_stream_order(tsd, stream_is_inorder);

            // don't queue data if we are ignoring or queue thresholds are exceeded
            if ( !tsd.are_packet_flags_set(PKT_IGNORE) and !flow_exceeds_config_thresholds(tsd) )
            {
                set_packet_header_foo(tsd);
                listener->reassembler.queue_packet_for_reassembly(tsd);

                // Alert if overlap limit exceeded
                if ( (tcp_config->overlap_limit)
                    && (listener->reassembler.get_overlap_count() > tcp_config->overlap_limit) )
                {
                    tel.set_tcp_event(EVENT_EXCESSIVE_OVERLAP);
                    listener->reassembler.set_overlap_count(0);
                }
            }
            break;

        case TcpNormalizer::NORM_TRIMMED:
            break;

        case TcpNormalizer::NORM_BAD_SEQ:
            return;

        default:
            assert(false);
            break;

        }
    }

    if ( flush )
        listener->reassembler.flush_on_data_policy(tsd.get_pkt());
    else
        listener->reassembler.initialize_paf();
}

TcpStreamTracker::TcpState TcpSession::get_talker_state(TcpSegmentDescriptor& tsd)
{
    return tsd.get_talker()->get_tcp_state();
}

TcpStreamTracker::TcpState TcpSession::get_listener_state(TcpSegmentDescriptor& tsd)
{
    return tsd.get_listener()->get_tcp_state();
}

void TcpSession::check_for_repeated_syn(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();
    TcpStreamTracker* talker = tsd.get_talker();
    uint32_t action = ACTION_NOTHING;

    if ( !SEQ_EQ(tsd.get_seq(), talker->get_iss()) and
        listener->normalizer.packet_dropper(tsd, NORM_TCP_BLOCK) )
    {
        set_pkt_action_flag(ACTION_BAD_PKT);
    }
    else if ( talker->get_tcp_state() >= TcpStreamTracker::TCP_ESTABLISHED and
        talker->get_tcp_state() < TcpStreamTracker::TCP_CLOSED )
    {
        action = listener->normalizer.handle_repeated_syn(tsd);
    }

    if (action != ACTION_NOTHING)
    {
        tel.set_tcp_event(EVENT_SYN_ON_EST);
        pkt_action_mask |= action;
    }
}

void TcpSession::flush_server(Packet* p)
{
    if ( !tcp_init )
        return;

    server.set_tf_flags(TF_FORCE_FLUSH);

    // don't flush if rebuilt packet, that would overwrite the packet being processed.
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return; // We'll check & clear the TF_FORCE_FLUSH next time through

    // Need to convert the addresses to network order
    if ( server.reassembler.flush_stream(p, PKT_FROM_SERVER) )
        server.reassembler.purge_flushed_ackd();

    server.clear_tf_flags(TF_FORCE_FLUSH);
}

void TcpSession::flush_client(Packet* p)
{
    if ( !tcp_init )
        return;

    client.set_tf_flags(TF_FORCE_FLUSH);

    // If rebuilt packet, don't flush now because we'll overwrite the packet being processed.
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;         // TF_FORCE_FLUSH checked & cleared next time through

    if ( client.reassembler.flush_stream(p, PKT_FROM_CLIENT) )
        client.reassembler.purge_flushed_ackd();

    client.clear_tf_flags(TF_FORCE_FLUSH);
}

void TcpSession::flush_tracker(
    TcpStreamTracker& tracker, Packet* p, uint32_t dir, bool final_flush)
{
    if ( final_flush && (!tracker.get_splitter() || !tracker.get_splitter()->finish(flow)) )
         return;

     tracker.set_tf_flags(TF_FORCE_FLUSH);
     if ( tracker.reassembler.flush_stream(p, dir, final_flush) )
         tracker.reassembler.purge_flushed_ackd();

     tracker.clear_tf_flags(TF_FORCE_FLUSH);
}

void TcpSession::flush_listener(Packet* p, bool final_flush)
{
    // direction of flush is the data from the opposite side
    if ( p->is_from_server() )
        flush_tracker( client, p, PKT_FROM_SERVER, final_flush);
    else if ( p->is_from_client() )
        flush_tracker( server, p, PKT_FROM_CLIENT, final_flush);
}

void TcpSession::flush_talker(Packet* p, bool final_flush)
{
    // direction of flush is the data from the opposite side
    if ( p->is_from_server() )
        flush_tracker( server, p, PKT_FROM_CLIENT, final_flush);
    else if ( p->is_from_client() )
        flush_tracker( client, p, PKT_FROM_SERVER, final_flush);
}

// if not in the context of a wire packet the caller must create a packet context
// by calling DetectionEngine::set_next_packet() before calling TcpSession::flush()
void TcpSession::flush()
{
    if ( !tcp_init )
        return;

    //FIXIT-L Cleanup tcp_init and lws_init as they have some side effect in TcpSession::clear_session
    lws_init = false;
    tcp_init = false;

    client.reassembler.flush_queued_segments(flow, true);
    server.reassembler.flush_queued_segments(flow, true);

    lws_init = true;
    tcp_init = true;
}

void TcpSession::set_extra_data(Packet* p, uint32_t xid)
{
    TcpStreamTracker& st = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ? server : client;
    st.reassembler.set_xtradata_mask(st.reassembler.get_xtradata_mask() | BIT(xid));
}

static inline void set_window_scale(TcpSegmentDescriptor& tsd)
{
    // scale the window.  Only if BOTH client and server specified wscale option as part
    // of 3-way handshake.  This is per RFC 1323.
    if ( (tsd.get_talker()->get_tf_flags() & TF_WSCALE)
         && (tsd.get_listener()->get_tf_flags() & TF_WSCALE) )
    {
        tsd.scale_wnd(tsd.get_talker()->get_wscale());
    }
}

void TcpSession::check_events_and_actions(const TcpSegmentDescriptor& tsd)
{
    tel.log_tcp_events();

    if ( tsd.is_meta_ack_packet() )
        return;

    Packet* p = tsd.get_pkt();
    if ( !(pkt_action_mask & ACTION_LWSSN_CLOSED) )
    {
        flow->markup_packet_flags(p);
        flow->set_expire(p, flow->default_session_timeout);
    }
    else
        TcpHAManager::process_deletion(*flow);

    if ( pkt_action_mask & ACTION_DISABLE_INSPECTION )
        DetectionEngine::disable_all(p);
}

bool TcpSession::ignore_this_packet(Packet* p)
{
    if ( no_ack_mode_enabled() and p->is_retry() )
    {
        // Don't need to process a retry packet through stream again,
        // just make sure the retransmit handler is called so that
        // we do things like update file inspection.
        flow->call_handlers(p, false);
        return true;
    }

    if ( Stream::blocked_flow(p) )
        return true;

    if ( flow->ssn_state.ignore_direction != SSN_DIR_NONE )
    {
        server.set_flush_policy(STREAM_FLPOLICY_IGNORE);
        client.set_flush_policy(STREAM_FLPOLICY_IGNORE);
        return true;
    }

    return false;
}

void TcpSession::cleanup_session_if_expired(Packet* p)
{
    // Check if the session is expired. Should be done before we do something with
    // the packet...Insert a packet, or handle state change SYN, FIN, RST, etc.
    if ( Stream::expired_flow(flow, p) )
    {
        /* Session is timed out, if also reset then restart, otherwise clear */
        if ( flow->get_session_flags() & SSNFLAG_RESET )
            clear_session(true, true, true, p);
        else
            clear_session(true, true, false, p);

        tcpStats.timeouts++;
        TcpHAManager::process_deletion(*flow);
    }
}

void TcpSession::precheck(Packet* p)
{
    // Check if the session is expired. Should be done before we do something with
    // the packet...Insert a packet, or handle state change SYN, FIN, RST, etc.
    cleanup_session_if_expired(p);
}

void TcpSession::init_tcp_packet_analysis(TcpSegmentDescriptor& tsd)
{
    if ( !splitter_init and tsd.is_data_segment() and
        (tcp_init or is_midstream_allowed(tsd)) )
    {
        if ( !(tcp_config->flags & STREAM_CONFIG_NO_REASSEMBLY) and
                !(tsd.get_flow()->flags.disable_reassembly_by_ips) )
        {
            client.set_splitter(tsd.get_flow());
            server.set_splitter(tsd.get_flow());

            client.init_flush_policy();
            server.init_flush_policy();

            set_no_ack(tcp_config->no_ack);
        }

        splitter_init = true;
    }

    pkt_action_mask = ACTION_NOTHING;
    tel.clear_tcp_events();
    // process thru state machine...talker first
    // When in no-ack mode, don't trust ACK numbers. Set the ACK value
    // as if the last packet in the other direction was ACK'd.
    // FIXIT-M: The snd_nxt and snd_una checks are only needed because
    // the snd_nxt value isn't valid for SYN/ACK packet. Can remove those
    // checks if that is fixed.
    if ( tsd.is_packet_from_client() )
    {
        update_session_on_client_packet(tsd);

        if ( no_ack_mode_enabled() and (server.get_snd_nxt() or server.get_snd_una()) )
            tsd.set_ack(server.get_snd_nxt());
    }
    else
    {
        update_session_on_server_packet(tsd);

        if ( no_ack_mode_enabled() and (client.get_snd_nxt() or client.get_snd_una()) )
            tsd.set_ack(client.get_snd_nxt());
    }

    update_ignored_session(tsd);
    set_window_scale(tsd);
}

bool TcpSession::validate_packet_established_session(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* listener = tsd.get_listener();

    if ( tsd.is_nap_policy_inline() )
       if ( tsd.get_tcph()->is_ack() && !listener->is_ack_valid(tsd.get_ack()) )
       {
           listener->normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
           set_pkt_action_flag(ACTION_BAD_PKT);
       }

    if ( !tsd.is_meta_ack_packet() )
        set_pkt_action_flag(listener->normalizer.handle_paws(tsd));

    return ( pkt_action_mask & ACTION_BAD_PKT ) ? false : true;
}

int TcpSession::process_tcp_packet(TcpSegmentDescriptor& tsd, const Packet* p)
{
    tsm->eval(tsd);
    check_events_and_actions(tsd);

    S5TraceTCP(tsd, p);

    return ACTION_NOTHING;
}

int TcpSession::process(Packet* p)
{
    Profile profile(s5TcpPerfStats);    // cppcheck-suppress unreadVariable
    assert(flow->ssn_server && flow->pkt_type == PktType::TCP);

    if ( ignore_this_packet(p) )
        return ACTION_NOTHING;

    TcpSegmentDescriptor tsd(flow, p, tel);
    init_tcp_packet_analysis(tsd);

    // check for and process meta-ack info first if present, the current listener is the
    // talker for the meta-ack...
    DAQ_PktTcpAckData_t* tcp_mack = (DAQ_PktTcpAckData_t*)p->daq_msg->meta[DAQ_PKT_META_TCP_ACK_DATA];
    if ( tcp_mack )
    {
        TcpSegmentDescriptor ma_tsd(flow, p, tcp_mack->tcp_ack_seq_num, tcp_mack->tcp_window_size);
        init_tcp_packet_analysis(ma_tsd);
        process_tcp_packet(ma_tsd, p);
        tcpStats.meta_acks++;
    }

    if ( p->context->conf->is_address_anomaly_check_enabled() )
        check_for_session_hijack(tsd);

    if ( ( flow->get_session_flags() & SSNFLAG_RESET ) && tsd.get_tcph()->is_syn()
            && !handle_syn_on_reset_session(tsd) )
        return ACTION_NOTHING;

    return process_tcp_packet(tsd, p);
}
