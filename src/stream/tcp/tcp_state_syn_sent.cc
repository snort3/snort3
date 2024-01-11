//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_syn_sent.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Aug 5, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_syn_sent.h"

#include "tcp_session.h"

using namespace snort;

TcpStateSynSent::TcpStateSynSent(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_SYN_SENT, tsm)
{ }

bool TcpStateSynSent::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateSynSent::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.irs = tsd.get_seq();
    trk.finish_client_init(tsd);
    if ( tsd.is_data_segment() )
        trk.session->handle_data_on_syn(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_SYN_RECV);
    return true;
}

bool TcpStateSynSent::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->flow->two_way_traffic() )
    {
        trk.session->check_for_repeated_syn(tsd);
        trk.update_tracker_ack_sent(tsd);
        trk.iss = tsd.get_seq();
        trk.session->update_timestamp_tracking(tsd);
    }
    return true;
}

bool TcpStateSynSent::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.session->flow->two_way_traffic() )
    {
        if ( trk.update_on_3whs_ack(tsd) )
        {
            trk.session->update_timestamp_tracking(tsd);
            if ( tsd.is_data_segment() )
                trk.session->handle_data_on_syn(tsd);
        }
        else
            trk.session->set_pkt_action_flag(ACTION_BAD_PKT);
    }

    return true;
}

bool TcpStateSynSent::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    trk.session->update_timestamp_tracking(tsd);
    if ( trk.session->flow->two_way_traffic() )
    {
        TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
        // Weird case with c2s syn, c2s syn seq + 1, s2c syn-ack to 2nd syn, c2s ack
        if ( TcpStreamTracker::TCP_SYN_RECV == listener_state )
        {
            trk.session->set_established(tsd);
            trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }
    return true;
}

bool TcpStateSynSent::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    // Finish handshake
    if ( trk.session->flow->two_way_traffic() )
        trk.update_on_3whs_ack(tsd);
    else
    {
        trk.update_tracker_ack_recv(tsd);
        trk.session->set_established(tsd);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    }
    return true;
}

bool TcpStateSynSent::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    trk.session->update_timestamp_tracking(tsd);
    if ( trk.session->flow->two_way_traffic() )
    {
        TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
        // Weird case with c2s syn, c2s syn seq + 1, s2c syn-ack to 2nd syn, c2s ack
        if ( TcpStreamTracker::TCP_SYN_RECV == listener_state )
        {
            trk.session->set_established(tsd);
            trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
    }
    return true;
}

bool TcpStateSynSent::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    ack_recv(tsd, trk);
    trk.session->handle_data_segment(tsd);
    return true;
}

bool TcpStateSynSent::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_on_fin_sent(tsd);
    trk.session->flow->call_handlers(tsd.get_pkt(), true);
    trk.session->update_timestamp_tracking(tsd);
    if ( trk.session->flow->two_way_traffic() )
    {
        TcpStreamTracker::TcpState listener_state = tsd.get_listener()->get_tcp_state();
        // Weird case with c2s syn, c2s syn seq + 1, s2c syn-ack to 2nd syn, c2s ack
        if ( TcpStreamTracker::TCP_SYN_RECV == listener_state )
        {
            trk.session->set_established(tsd);
            trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
        }
        trk.set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT1);
    }
    return true;
}

bool TcpStateSynSent::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.set_fin_seq_status_seen(tsd);
    ack_recv(tsd, trk);
    if ( trk.session->flow->two_way_traffic() )
    {
        if ( trk.update_on_fin_recv(tsd) )
        {
            trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
            trk.set_tcp_state(TcpStreamTracker::TCP_CLOSE_WAIT);
        }
    }
    trk.perform_fin_recv_flush(tsd);
    return true;
}

bool TcpStateSynSent::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, false);
        trk.set_tcp_state(TcpStreamTracker::TCP_CLOSED);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSED);
        trk.session->set_pkt_action_flag(ACTION_RST);
        tsd.get_flow()->session_state |= STREAM_STATE_CLOSED;
    }

    // FIXIT-L might be good to create alert specific to RST with data
    if ( tsd.is_data_segment() )
        trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);

    return true;
}

bool TcpStateSynSent::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_window_slam(tsd);

    return true;
}

