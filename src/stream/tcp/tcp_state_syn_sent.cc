//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

using namespace std;

TcpStateSynSent::TcpStateSynSent(TcpStateMachine& tsm) :
    TcpStateHandler(TcpStreamTracker::TCP_SYN_SENT, tsm)
{
}

bool TcpStateSynSent::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->check_for_repeated_syn(tsd);
    return true;
}

bool TcpStateSynSent::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.finish_client_init(tsd);
    if ( tsd.get_seg_len() )
        trk.session->handle_data_on_syn(tsd);
    trk.set_tcp_state(TcpStreamTracker::TCP_SYN_RECV);
    return true;
}

bool TcpStateSynSent::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( trk.update_on_3whs_ack(tsd) )
    {
        trk.session->update_timestamp_tracking(tsd);
        if ( tsd.get_seg_len() )
            trk.session->handle_data_on_syn(tsd);
    }
    else
        trk.session->set_pkt_action_flag(ACTION_BAD_PKT);
    return true;
}

bool TcpStateSynSent::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    snort::Flow* flow = tsd.get_flow();

    // FIXIT-H verify ack being sent is valid...
    trk.update_tracker_ack_sent(tsd);
    flow->set_session_flags(SSNFLAG_ESTABLISHED);
    flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );
    trk.session->update_timestamp_tracking(tsd);
    trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

bool TcpStateSynSent::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.get_seg_len() > 0 )
        trk.session->handle_data_segment(tsd);
    return true;
}

bool TcpStateSynSent::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    snort::Flow* flow = tsd.get_flow();

    // FIXIT-H verify ack being sent is valid...
    trk.update_tracker_ack_sent(tsd);
    flow->set_session_flags(SSNFLAG_ESTABLISHED);
    flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );
    trk.session->update_timestamp_tracking(tsd);
    trk.session->update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
    trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    return true;
}

bool TcpStateSynSent::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    trk.session->handle_data_segment(tsd);
    return true;
}

bool TcpStateSynSent::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)
{
    if ( tsd.get_seg_len() > 0 )
        trk.session->handle_data_segment(tsd);
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
        tsd.get_pkt()->flow->session_state |= STREAM_STATE_CLOSED;
    }
    else
    {
        trk.session->tel.set_tcp_event(EVENT_BAD_RST);
    }

    // FIXIT-L might be good to create alert specific to RST with data
    if ( tsd.get_seg_len() > 0 )
        trk.session->tel.set_tcp_event(EVENT_DATA_AFTER_RST_RCVD);
    return true;
}

