//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "framework/data_bus.h"
#include "log/log.h"
#include "packet_io/packet_tracer.h"
#include "profiler/profiler.h"
#include "protocols/eth.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"

#include "stream_tcp.h"
#include "tcp_ha.h"
#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_segment_node.h"
#include "tcp_state_machine.h"
#include "tcp_trace.h"
#include "trace/trace_api.h"

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

TcpSession::TcpSession(Flow* f)
    : Session(f), client(true), server(false)
{
    tsm = TcpStateMachine::get_instance();
    client.init_tcp_state(this);
    server.init_tcp_state(this);

    tcpStats.instantiated++;
}

TcpSession::~TcpSession()
{
    clear_session(true, false, false);
}

bool TcpSession::setup(Packet*)
{
    client.init_tcp_state(this);
    server.init_tcp_state(this);
    tcp_init = false;
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
        talker->reassembler->eval_flush_policy_on_data(p);
    }

    if (p->dsize > 0)
        listener->reassembler->eval_flush_policy_on_data(p);

    if (p->ptrs.tcph->is_ack())
        talker->reassembler->eval_flush_policy_on_ack(p);

    tcpStats.restarts++;
}

// if the flush_segments parameter is true and clear_session is being called while not in
// the context of a wire packet then the caller must create a packet context by calling
// DetectionEngine::set_next_packet() before calling clear_session
void TcpSession::clear_session(bool free_flow_data, bool flush_segments, bool restart, Packet* p)
{
    assert(!p or p->flow == flow);
    if ( !tcp_init )
        return;

    tcp_init = false;
    tcpStats.released++;

    if ( is_data_transferred_asymmetrically() and free_flow_data )
        tcpStats.asymmetric_flows++;

    client.clear_tracker(flow, p, flush_segments, restart);
    server.clear_tracker(flow, p, flush_segments, restart);
    update_perf_base_state(TcpStreamTracker::TCP_CLOSED);
    tel.log_internal_event(SESSION_EVENT_CLEAR);

    if ( restart )
        flow->restart(free_flow_data);
    else
        flow->clear(free_flow_data);
}

bool TcpSession::is_data_transferred_asymmetrically() const
{
    return !flow->two_way_traffic()
        && (client.seglist.data_was_queued() != server.seglist.data_was_queued());
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

void TcpSession::check_flow_missed_3whs()
{
    if ( flow->two_way_traffic() )
        return;

    if ( PacketTracer::is_active() )
        PacketTracer::log("stream_tcp: TCP did not see the complete 3-Way Handshake. "
        "Not all normalizations will be in effect\n");

    client.normalizer.init(StreamPolicy::MISSED_3WHS, this, &client, &server);
    server.normalizer.init(StreamPolicy::MISSED_3WHS, this, &server, &client);
}

void TcpSession::set_os_policy()
{
    assert(tcp_config->policy <= StreamPolicy::OS_VISTA);

    StreamPolicy client_os_policy = flow->ssn_policy ?
        static_cast<StreamPolicy>( flow->ssn_policy ) : tcp_config->policy;

    StreamPolicy server_os_policy = flow->ssn_policy ?
        static_cast<StreamPolicy>( flow->ssn_policy ) : tcp_config->policy;

    client.normalizer.init(client_os_policy, this, &client, &server);
    server.normalizer.init(server_os_policy, this, &server, &client);

    if (Normalize_GetMode(NORM_TCP_IPS) == NORM_MODE_ON)
    {
        client_os_policy = StreamPolicy::OS_FIRST;
        server_os_policy = StreamPolicy::OS_FIRST;
    }

    client.seglist.init(this, &client, client_os_policy);
    server.seglist.init(this, &server, server_os_policy);
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
            listener->normalizer.ecn_tracker(tcph);
            flow->update_session_flags(SSNFLAG_SEEN_CLIENT);
        }
        else if ( tcph->is_syn_ack() )
        {
            flow->ssn_state.direction = FROM_SERVER;
            flow->set_ttl(tsd.get_pkt(), false);
            init_session_on_synack(tsd);
            tcpStats.resyns++;

            listener->normalizer.ecn_tracker(tcph);
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
        // skip the byte in sequence space for SYN...data starts at the next byte
        tsd.update_seq(1);
        handle_data_segment(tsd);
        tel.set_tcp_event(EVENT_DATA_ON_SYN);
    }
}

void TcpSession::update_session_on_rst(const TcpSegmentDescriptor& tsd, bool flush)
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
    if (Stream::is_midstream(tsd.get_flow()) or !flow->two_way_traffic())
        return false;

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
        && !(tsd.get_tcph()->is_fin() || tsd.get_tcph()->is_rst()))
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

bool TcpSession::check_reassembly_queue_thresholds(TcpSegmentDescriptor& tsd, TcpStreamTracker* listener)
{
    // if this packet fits within the current queue limit window then it's good
    if( listener->seglist.segment_within_seglist_window(tsd) )
        return false;

    bool inline_mode = tsd.is_nap_policy_inline();

    if ( tcp_config->max_queued_bytes )
    {
        int32_t space_left =
            tcp_config->max_queued_bytes - listener->seglist.get_seg_bytes_total();

        if ( space_left < (int32_t)tsd.get_len() )
        {
            tcpStats.exceeded_max_bytes++;
            bool ret_val = true;

            // if this is an asymmetric flow then skip over any seglist holes
            // and flush to free up seglist space
            if ( !tsd.get_pkt()->flow->two_way_traffic() )
            {
                space_left = listener->kickstart_asymmetric_flow(tsd, tcp_config->max_queued_bytes);
                if ( space_left >= (int32_t)tsd.get_len() )
                    return false;
            }

            if ( space_left > 0 )
                ret_val = !inline_mode; // For partial trim, reassemble only if we can force an inject
            else
                space_left = 0;

            if ( inline_mode || listener->normalizer.get_trim_win() == NORM_MODE_ON)
            {
                // FIXIT-M - only alert once per threshold exceeded event
                tel.set_tcp_event(EVENT_MAX_QUEUED_BYTES_EXCEEDED);
                listener->normalizer.log_drop_reason(tsd, inline_mode, "stream",
                    "stream_tcp: Flow exceeded the configured max byte threshold (" + std::to_string(tcp_config->max_queued_bytes) +
                    "). You may want to adjust the 'max_bytes' parameter in the NAP policy"
                    " to a higher value, or '0' for unlimited.\n");
            }

            listener->normalizer.trim_win_payload(tsd, space_left, inline_mode);
            return ret_val;
        }
    }

    if ( tcp_config->max_queued_segs )
    {
        if ( listener->seglist.get_seg_count() + 1 > tcp_config->max_queued_segs )
        {
            tcpStats.exceeded_max_segs++;

            // if this is an asymmetric flow then skip over any seglist holes
            // and flush to free up seglist space
            if ( !tsd.get_pkt()->flow->two_way_traffic() )
            {
                listener->kickstart_asymmetric_flow(tsd, tcp_config->max_queued_bytes);
                if ( listener->seglist.get_seg_count() + 1 <= tcp_config->max_queued_segs )
                    return false;
            }

            if ( inline_mode || listener->normalizer.get_trim_win() == NORM_MODE_ON)
            {
                // FIXIT-M - only alert once per threshold exceeded event
                tel.set_tcp_event(EVENT_MAX_QUEUED_SEGS_EXCEEDED);
                listener->normalizer.log_drop_reason(tsd, inline_mode, "stream",
                    "stream_tcp: Flow exceeded the configured max segment threshold (" + std::to_string(tcp_config->max_queued_segs) +
                    "). You may want to adjust the 'max_segments' parameter in the NAP policy"
                    " to a higher value, or '0' for unlimited.\n");
            }

            listener->normalizer.trim_win_payload(tsd, 0, inline_mode);
            return true;
        }
    }

    return false;
}

bool TcpSession::filter_packet_for_reassembly(TcpSegmentDescriptor& tsd, TcpStreamTracker* listener)
{
    if ( tsd.are_packet_flags_set(PKT_IGNORE)
        or listener->get_flush_policy() == STREAM_FLPOLICY_IGNORE
        or ( ( tcp_config->flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY ) && !flow->two_way_traffic() ) )
        return false;

    return !check_reassembly_queue_thresholds(tsd, listener);
}

void TcpSession::check_small_segment_threshold(const TcpSegmentDescriptor &tsd, TcpStreamTracker *listener)
{
    // alert if small segments threshold is exceeded
    if (tcp_config->max_consec_small_segs)
    {
        if (tsd.get_len() >= tcp_config->max_consec_small_seg_size)
            listener->small_seg_count = 0;
        else if (++listener->small_seg_count == tcp_config->max_consec_small_segs)
            tel.set_tcp_event(EVENT_MAX_SMALL_SEGS_EXCEEDED);
    }
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

        tsd.set_packet_inorder(tsd.get_seq() == listener->rcv_nxt );

        int rc =  listener->normalizer.apply_normalizations(tsd, tsd.get_seq(), tsd.is_packet_inorder());
        switch ( rc )
        {
        case TcpNormalizer::NORM_OK:
            check_small_segment_threshold(tsd, listener);

            // don't queue data if we are ignoring or queue thresholds are exceeded
            if ( filter_packet_for_reassembly(tsd, listener) )
            {
                set_packet_header_foo(tsd);
                listener->seglist.queue_reassembly_segment(tsd);

                // Alert if overlap limit exceeded
                if ( (tcp_config->overlap_limit)
                    && (listener->seglist.get_overlap_count() > tcp_config->overlap_limit) )
                {
                    tel.set_tcp_event(EVENT_EXCESSIVE_OVERLAP);
                    listener->seglist.set_overlap_count(0);
                }
            }
            else if ( tsd.is_packet_inorder() )
                listener->set_rcv_nxt(tsd.get_end_seq());

            listener->update_stream_order(tsd, tsd.is_packet_inorder());

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
        listener->reassembler->eval_flush_policy_on_data(tsd.get_pkt());
    else
        listener->reassembler->initialize_paf();
}

TcpStreamTracker::TcpState TcpSession::get_talker_state(const TcpSegmentDescriptor& tsd)
{
    return tsd.get_talker()->get_tcp_state();
}

TcpStreamTracker::TcpState TcpSession::get_listener_state(const TcpSegmentDescriptor& tsd)
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
    if ( server.reassembler->flush_stream(p, PKT_FROM_SERVER) )
        server.reassembler->purge_flushed_ackd();

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

    if ( client.reassembler->flush_stream(p, PKT_FROM_CLIENT) )
        client.reassembler->purge_flushed_ackd();

    client.clear_tf_flags(TF_FORCE_FLUSH);
}

void TcpSession::flush_tracker(
    TcpStreamTracker& tracker, Packet* p, uint32_t dir, bool final_flush)
{
    if ( final_flush && (!tracker.get_splitter() || !tracker.get_splitter()->finish(flow)) )
         return;

     tracker.set_tf_flags(TF_FORCE_FLUSH);
     if ( tracker.reassembler->flush_stream(p, dir, final_flush) )
         tracker.reassembler->purge_flushed_ackd();

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

    //FIXIT-L Cleanup tcp_init has some side effect in TcpSession::clear_session
    tcp_init = false;

    client.reassembler->flush_queued_segments(flow, true);
    server.reassembler->flush_queued_segments(flow, true);

    tcp_init = true;
}

void TcpSession::set_extra_data(Packet* p, uint32_t xid)
{
    TcpStreamTracker& st = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ? server : client;
    st.tcp_alerts.set_xtradata_mask(st.tcp_alerts.get_xtradata_mask() | BIT(xid));
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

    if ( flow->ssn_state.ignore_direction == SSN_DIR_BOTH )
    {
        server.set_splitter((StreamSplitter*)nullptr);
        client.set_splitter((StreamSplitter*)nullptr);
        return true;
    }

    return false;
}

bool TcpSession::cleanup_session_if_expired(Packet* p)
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

        return true;
    }
    return false;
}

bool TcpSession::precheck(Packet* p)
{
    // Check if the session is expired. Should be done before we do something with
    // the packet...Insert a packet, or handle state change SYN, FIN, RST, etc.
    return !cleanup_session_if_expired(p);
}

void TcpSession::init_tcp_packet_analysis(TcpSegmentDescriptor& tsd)
{
    if ( !splitter_init and tsd.is_data_segment() )
    {
        if ( !(tcp_config->flags & STREAM_CONFIG_NO_REASSEMBLY) and
                !(tsd.get_flow()->flags.disable_reassembly_by_ips) )
        {
            client.set_splitter(tsd.get_flow());
            server.set_splitter(tsd.get_flow());

            if ( tsd.is_packet_from_client() ) // Important if the 3-way handshake's ACK contains data
                flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
            else
                flow->set_session_flags(SSNFLAG_SEEN_SERVER);

            check_flow_missed_3whs();
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

    if ( stream_tcp_trace_enabled )
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
        assert( ma_tsd.get_pkt()->daq_msg and ma_tsd.get_pkt()->daq_msg == p->daq_msg );
        assert( ma_tsd.get_pkt()->daq_instance and ma_tsd.get_pkt()->daq_instance == p->daq_instance );

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

void TcpSession::init_new_tcp_session(TcpSegmentDescriptor& tsd)
{
    Packet* p = tsd.get_pkt();

    flow->pkt_type = p->type();
    flow->ip_proto = (uint8_t)p->get_ip_proto_next();

    /* New session, previous was marked as reset.  Clear the reset flag. */
    flow->clear_session_flags(SSNFLAG_RESET);

    flow->set_expire(p, flow->default_session_timeout);

    update_perf_base_state(TcpStreamTracker::TCP_SYN_SENT);

    tcp_init = true;
}

void TcpSession::update_session_on_server_packet(TcpSegmentDescriptor& tsd)
{
    flow->set_session_flags(SSNFLAG_SEEN_SERVER);
    tsd.set_talker(server);
    tsd.set_listener(client);

    if ( !flow->inner_server_ttl && !tsd.is_meta_ack_packet() )
        flow->set_ttl(tsd.get_pkt(), false);
}

void TcpSession::update_session_on_client_packet(TcpSegmentDescriptor& tsd)
{
    /* if we got here we have seen the SYN already... */
    flow->set_session_flags(SSNFLAG_SEEN_CLIENT);
    tsd.set_talker(client);
    tsd.set_listener(server);

    if ( !flow->inner_client_ttl && !tsd.is_meta_ack_packet() )
        flow->set_ttl(tsd.get_pkt(), true);
}

bool TcpSession::can_set_no_ack()
{
    return ( server.get_flush_policy() == STREAM_FLPOLICY_ON_DATA and
         client.get_flush_policy() == STREAM_FLPOLICY_ON_DATA );
}

bool TcpSession::set_no_ack(bool b)
{
    if ( can_set_no_ack() )
    {
        no_ack = b;
        return true;
    }
    else
        return false;
}

void TcpSession::disable_reassembly(Flow* f)
{
    client.disable_reassembly(f);
    server.disable_reassembly(f);
}

bool TcpSession::is_sequenced(uint8_t dir) const
{
    if ( dir & SSN_DIR_FROM_CLIENT )
    {
        if ( server.get_tf_flags() & ( TF_MISSING_PREV_PKT | TF_PKT_MISSED ) )
            return false;
    }

    if ( dir & SSN_DIR_FROM_SERVER )
    {
        if ( client.get_tf_flags() & ( TF_MISSING_PREV_PKT | TF_PKT_MISSED ) )
            return false;
    }

    return true;
}

/* This will falsely return SSN_MISSING_BEFORE on the first reassembled
 * packet if reassembly for this direction was set mid-session */
uint8_t TcpSession::missing_in_reassembled(uint8_t dir) const
{
    if ( dir & SSN_DIR_FROM_CLIENT )
    {
        if ( (server.get_tf_flags() & TF_MISSING_PKT)
            && (server.get_tf_flags() & TF_MISSING_PREV_PKT) )
            return SSN_MISSING_BOTH;
        else if ( server.get_tf_flags() & TF_MISSING_PREV_PKT )
            return SSN_MISSING_BEFORE;
        else if ( server.get_tf_flags() & TF_MISSING_PKT )
            return SSN_MISSING_AFTER;
    }
    else if ( dir & SSN_DIR_FROM_SERVER )
    {
        if ( (client.get_tf_flags() & TF_MISSING_PKT)
            && (client.get_tf_flags() & TF_MISSING_PREV_PKT) )
            return SSN_MISSING_BOTH;
        else if ( client.get_tf_flags() & TF_MISSING_PREV_PKT )
            return SSN_MISSING_BEFORE;
        else if ( client.get_tf_flags() & TF_MISSING_PKT )
            return SSN_MISSING_AFTER;
    }

    return SSN_MISSING_NONE;
}

bool TcpSession::are_packets_missing(uint8_t dir) const
{
    if ( dir & SSN_DIR_FROM_CLIENT )
    {
        if ( server.get_tf_flags() & TF_PKT_MISSED )
            return true;
    }

    if ( dir & SSN_DIR_FROM_SERVER )
    {
        if ( client.get_tf_flags() & TF_PKT_MISSED )
            return true;
    }

    return false;
}

bool TcpSession::are_client_segments_queued() const
{
    return client.seglist.is_segment_pending_flush();
}

bool TcpSession::add_alert(Packet* p, uint32_t gid, uint32_t sid)
{
    TcpStreamTracker& trk = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ?
        server : client;

    return trk.tcp_alerts.add_alert(gid, sid);
}

bool TcpSession::check_alerted(Packet* p, uint32_t gid, uint32_t sid)
{
    // only check for alert on wire packet, skip this when processing a rebuilt packet
    if ( !(p->packet_flags & PKT_REBUILT_STREAM) )
        return false;

    TcpStreamTracker& trk = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ?
          server : client;

    return trk.tcp_alerts.check_alerted(gid, sid);
}

int TcpSession::update_alert(Packet* p, uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
      TcpStreamTracker& trk = p->ptrs.ip_api.get_src()->equals(flow->client_ip) ?
            server : client;

    return trk.tcp_alerts.update_alert(gid, sid, event_id, event_second);
}

bool TcpSession::set_packet_action_to_hold(Packet* p)
{
    if ( p->is_from_client() )
    {
        held_packet_dir = SSN_DIR_FROM_CLIENT;
        return server.set_held_packet(p);
    }
    else
    {
        held_packet_dir = SSN_DIR_FROM_SERVER;
        return client.set_held_packet(p);
    }
}

void TcpSession::set_packet_header_foo(const TcpSegmentDescriptor& tsd)
{
    const Packet* p = tsd.get_pkt();

    if ( tsd.is_packet_from_client() || (p->pkth->egress_index == DAQ_PKTHDR_UNKNOWN
         && p->pkth->egress_group == DAQ_PKTHDR_UNKNOWN) )
    {
        ingress_index = p->pkth->ingress_index;
        ingress_group = p->pkth->ingress_group;
        // ssn egress may be unknown, but will be correct
        egress_index = p->pkth->egress_index;
        egress_group = p->pkth->egress_group;
    }
    else
    {
        egress_index = p->pkth->ingress_index;
        egress_group = p->pkth->ingress_group;
        ingress_index = p->pkth->egress_index;
        ingress_group = p->pkth->egress_group;
    }

    daq_flags = p->pkth->flags;
    address_space_id = p->pkth->address_space_id;
}

void TcpSession::get_packet_header_foo(DAQ_PktHdr_t* pkth, const DAQ_PktHdr_t* orig, uint32_t dir)
{
    if ( (dir & PKT_FROM_CLIENT) || (egress_index == DAQ_PKTHDR_UNKNOWN &&
         egress_group == DAQ_PKTHDR_UNKNOWN) )
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
    pkth->tenant_id = orig->tenant_id;
}

void TcpSession::reset()
{
    if ( tcp_init )
        clear_session(true, false, false );
}

void TcpSession::cleanup(Packet* p)
{
    if ( cleaning )
        return;

    cleaning = true;
    clear_session(true, true, false, p);
    client.reset();
    server.reset();
    cleaning = false;
}

void TcpSession::clear()
{
    if ( tcp_init )
        clear_session( true, false, false );

    TcpHAManager::process_deletion(*flow);
}

void TcpSession::set_splitter(bool to_server, StreamSplitter* ss)
{
    TcpStreamTracker& trk = ( to_server ) ? server : client;

    trk.set_splitter(ss);
}

uint16_t TcpSession::get_mss(bool to_server) const
{
    const TcpStreamTracker& trk = (to_server) ? client : server;

    return trk.get_mss();
}

uint8_t TcpSession::get_tcp_options_len(bool to_server) const
{
    const TcpStreamTracker& trk = (to_server) ? client : server;

    return trk.get_tcp_options_len();
}

StreamSplitter* TcpSession::get_splitter(bool to_server)
{
    if ( to_server )
        return server.get_splitter();
    else
        return client.get_splitter();
}

void TcpSession::start_proxy()
{
    if ( PacketTracer::is_active() )
        PacketTracer::log("stream_tcp: TCP normalization policy set to Proxy mode. Normalizations will be skipped\n");

    client.normalizer.init(StreamPolicy::OS_PROXY, this, &client, &server);
    server.normalizer.init(StreamPolicy::OS_PROXY, this, &server, &client);
    ++tcpStats.proxy_mode_flows;
}

void TcpSession::set_established(const TcpSegmentDescriptor& tsd)
{
    update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    flow->session_state |= STREAM_STATE_ESTABLISHED;
    flow->set_idle_timeout(this->tcp_config->idle_timeout);
    if (SSNFLAG_ESTABLISHED != (SSNFLAG_ESTABLISHED & flow->get_session_flags()))
    {
        flow->set_session_flags(SSNFLAG_ESTABLISHED);
        // Only send 1 event
        if (SSNFLAG_TCP_PSEUDO_EST != (SSNFLAG_TCP_PSEUDO_EST & flow->get_session_flags()))
            DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_ESTABLISHED, tsd.get_pkt());
    }
}

void TcpSession::set_pseudo_established(Packet* p)
{
    p->flow->ssn_state.session_flags |= SSNFLAG_TCP_PSEUDO_EST;
    DataBus::publish(Stream::get_pub_id(), StreamEventIds::TCP_ESTABLISHED, p);
}

bool TcpSession::check_for_one_sided_session(Packet* p)
{
    Flow& flow = *p->flow;
    if ( 0 == ( (SSNFLAG_ESTABLISHED | SSNFLAG_TCP_PSEUDO_EST) & flow.ssn_state.session_flags )
        && p->is_from_client_originally() )
    {
        uint64_t initiator_packets;
        uint64_t responder_packets;
        if (flow.flags.client_initiated)
        {
            initiator_packets = flow.flowstats.client_pkts;
            responder_packets = flow.flowstats.server_pkts;
        }
        else
        {
            initiator_packets = flow.flowstats.server_pkts;
            responder_packets = flow.flowstats.client_pkts;
        }

        if ( !responder_packets )
        {
            // handle case where traffic is only in one direction, but the sequence numbers
            // are changing indicating an asynchronous session
            uint32_t watermark = p->ptrs.tcph->seq() + p->ptrs.tcph->ack();
            if ( 1 == initiator_packets )
                initiator_watermark = watermark;
            else if ( initiator_watermark != watermark )
            {
                set_pseudo_established(p);
                return true;
            }
        }
    }
    return false;
}

void TcpSession::check_for_pseudo_established(Packet* p)
{
    Flow& flow = *p->flow;
    if ( 0 == ( (SSNFLAG_ESTABLISHED | SSNFLAG_TCP_PSEUDO_EST) & flow.ssn_state.session_flags ) )
    {
        if ( check_for_one_sided_session(p) )
            return;
        if ( 0 < flow.flowstats.client_pkts && 0 < flow.flowstats.server_pkts )
            set_pseudo_established(p);
    }
}


