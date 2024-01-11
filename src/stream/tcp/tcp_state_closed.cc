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

// tcp_state_closed.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_closed.h"

#include "tcp_session.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

TcpStateClosed::TcpStateClosed(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_CLOSED, tsm)
{ }

bool TcpStateClosed::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateClosed::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();
    flow->set_expire(tsd.get_pkt(), trk.session->tcp_config->session_timeout);
    return true;
}

bool TcpStateClosed::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateClosed::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    return true;
}

bool TcpStateClosed::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    Flow* flow = tsd.get_flow();

    trk.update_tracker_ack_sent(tsd);
    // data on a segment when we're not accepting data any more alert!
    if ( flow->get_session_flags() & SSNFLAG_RESET )
    {
        if ( trk.is_rst_pkt_sent() )
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RESET);
        else
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
    }
    else
        trk.session->tel.set_tcp_event(EVENT_DATA_ON_CLOSED);

    trk.session->mark_packet_for_drop(tsd);
    return true;
}

bool TcpStateClosed::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);
    return true;
}

bool TcpStateClosed::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_sent(tsd);
    return true;
}

bool TcpStateClosed::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.update_tracker_ack_recv(tsd);

    if( tsd.is_data_segment() )
    {
        if ( trk.is_rst_pkt_sent() )
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RESET);
        else
            trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
    }
    return true;
}

bool TcpStateClosed::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_rst_recv(tsd) )
    {
        trk.session->update_session_on_rst(tsd, false);
        trk.session->update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        trk.session->set_pkt_action_flag(ACTION_RST);
    }

    return true;
}

bool TcpStateClosed::do_pre_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    return trk.session->validate_packet_established_session(tsd);
}

bool TcpStateClosed::do_post_sm_packet_actions(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->update_paws_timestamps(tsd);
    trk.session->check_for_window_slam(tsd);

    if ( trk.get_tcp_event() != TcpStreamTracker::TCP_FIN_RECV_EVENT )
    {
        TcpStreamTracker::TcpState talker_state = trk.session->get_talker_state(tsd);
        Flow* flow = tsd.get_flow();

        if ( ( talker_state == TcpStreamTracker::TCP_TIME_WAIT or
               talker_state == TcpStreamTracker::TCP_CLOSED ) or !flow->two_way_traffic() )
        {
            // The last ACK is a part of the session. Delete the session after processing is
            // complete.
            trk.session->clear_session(false, true, false, tsd.is_meta_ack_packet() ? nullptr : tsd.get_pkt() );
            flow->session_state |= STREAM_STATE_CLOSED;
            trk.session->set_pkt_action_flag(ACTION_LWSSN_CLOSED);
        }
    }

    return true;
}

