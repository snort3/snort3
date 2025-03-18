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

// tcp_state_syn_recv.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Aug 5, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_syn_recv.h"

#include "tcp_module.h"
#include "tcp_normalizers.h"
#include "tcp_session.h"

using namespace snort;

TcpStateSynRecv::TcpStateSynRecv(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_SYN_RECV, tsm)
{ }

bool TcpStateSynRecv::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.finish_server_init(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph());
    trk.session->update_timestamp_tracking(tsd);
    Flow* flow = tsd.get_flow();
    if ( tsd.get_tcph()->are_flags_set(TH_ECE) &&
        ( flow->get_session_flags() & SSNFLAG_ECN_CLIENT_QUERY ) )
        flow->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

    if ( tsd.is_packet_from_server() )
    {
        flow->set_session_flags(SSNFLAG_SEEN_SERVER);
        trk.session->tel.set_tcp_event(EVENT_4WHS);
    }

    return true;
}

bool TcpStateSynRecv::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.is_data_segment() )
        trk.session->handle_data_on_syn(tsd);

    return true;
}

bool TcpStateSynRecv::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.finish_server_init(tsd);
    trk.normalizer.ecn_tracker(tsd.get_tcph());

    return true;
}

bool TcpStateSynRecv::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.is_ack_valid(tsd.get_ack()) )
    {
        trk.set_irs(tsd.get_seq());
        trk.update_tracker_ack_recv(tsd);
        trk.normalizer.ecn_tracker(tsd.get_tcph());
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        if ( tsd.is_data_segment() )
            trk.session->handle_data_on_syn(tsd);
    }

    return true;
}

bool TcpStateSynRecv::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->flow->two_way_traffic() )
    {
        TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
        // Does this ACK finish 4-way handshake
        if ( TcpStreamTracker::TCP_ESTABLISHED == listener_state )
        {
            trk.session->set_established(tsd);
            trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }
    return true;
}

bool TcpStateSynRecv::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( !tsd.is_meta_ack_packet() && trk.is_ack_valid(tsd.get_ack()) )
    {
        trk.update_tracker_ack_recv(tsd);
        trk.session->set_pkt_action_flag(trk.normalizer.handle_paws(tsd));
        tsd.set_packet_flags(PKT_STREAM_TWH);
        TcpStreamTracker::TcpState talker_state = tsd.get_talker()->get_tcp_state();
        // Does this ACK finish the 3-way or 4-way handshake
        if ( TcpStreamTracker::TCP_ESTABLISHED == talker_state || !trk.session->flow->two_way_traffic() )
            trk.session->set_established(tsd);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.session->check_for_window_slam(tsd);
    }
    return true;
}

bool TcpStateSynRecv::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);

    if ( trk.session->no_ack_mode_enabled() )
        trk.update_tracker_no_ack_recv(tsd);

    if ( trk.session->flow->two_way_traffic() )
    {
        TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
        // Does this ACK finish 4-way handshake
        if ( TcpStreamTracker::TCP_ESTABLISHED == listener_state )
        {
            trk.session->set_established(tsd);
            trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }
    return true;
}

bool TcpStateSynRecv::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    ack_recv(tsd, trk);
    trk.session->handle_data_segment(tsd);
    return true;
}

bool TcpStateSynRecv::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.get_tcph()->is_ack() )
    {
        trk.set_fin_seq_status_seen(tsd);
        trk.update_tracker_ack_recv(tsd);
        trk.session->set_pkt_action_flag(trk.normalizer.handle_paws(tsd));

        TcpStreamTracker::TcpState talker_state = tsd.get_talker()->get_tcp_state();
        // Does this ACK finish the 3-way
        if ( TcpStreamTracker::TCP_ESTABLISHED == talker_state
            || TcpStreamTracker::TCP_FIN_WAIT1 == talker_state )
            trk.session->set_established(tsd);

        trk.perform_fin_recv_flush(tsd);

        if ( trk.update_on_fin_recv(tsd) )
        {
            trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
            trk.set_tcp_state(TcpStreamTracker::TCP_CLOSE_WAIT);
        }
    }

    return true;
}

bool TcpStateSynRecv::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.normalizer.trim_rst_payload(tsd);
    if ( trk.normalizer.validate_rst(tsd) )
    {
        Flow* flow = tsd.get_flow();
        flow->set_session_flags(SSNFLAG_RESET);
        if ( !((SSNFLAG_TCP_PSEUDO_EST | SSNFLAG_ESTABLISHED) & flow->get_session_flags()) )
            trk.session->set_pseudo_established(tsd.get_pkt());
    }
    else
    {
        trk.session->tel.set_tcp_event(EVENT_BAD_RST);
        trk.normalizer.packet_dropper(tsd, NORM_TCP_BLOCK);
        trk.session->set_pkt_action_flag(ACTION_BAD_PKT);
    }

    // FIXIT-L might be good to create alert specific to RST with data
    if ( tsd.is_data_segment() )
        trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);

    return true;
}

bool TcpStateSynRecv::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_window_slam(tsd);

    return true;
}

