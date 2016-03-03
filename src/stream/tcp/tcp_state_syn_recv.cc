//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_syn_recv.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Aug 5, 2015

#include <iostream>
using namespace std;

#include "tcp_module.h"
#include "tcp_tracker.h"
#include "tcp_session.h"
#include "tcp_normalizer.h"
#include "tcp_state_syn_recv.h"

TcpStateSynRecv::TcpStateSynRecv(TcpStateMachine& tsm, TcpSession& ssn) :
    TcpStateHandler(TcpStreamTracker::TCP_SYN_RECV, tsm), session(ssn)
{
}

TcpStateSynRecv::~TcpStateSynRecv()
{
}

bool TcpStateSynRecv::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    Flow* flow = tsd.get_flow();
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.finish_server_init(tsd);
    trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
    session.update_timestamp_tracking(tsd);
    if ( tsd.get_tcph()->are_flags_set(TH_ECE) &&
        ( flow->get_session_flags() & SSNFLAG_ECN_CLIENT_QUERY ) )
        flow->set_session_flags(SSNFLAG_ECN_SERVER_REPLY);

    if ( tsd.get_pkt()->packet_flags & PKT_FROM_SERVER )
    {
        flow->set_session_flags(SSNFLAG_SEEN_SERVER);
        session.tel.set_tcp_event(EVENT_4WHS);
    }

    trk.s_mgr.sub_state |= SUB_SYN_SENT;

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( tsd.get_seg_len() )
        session.handle_data_on_syn(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    Flow* flow = tsd.get_flow();
    auto& trk = static_cast< TcpTracker& >( tracker );

    // FIXIT - verify ack being sent is valid...
    trk.finish_server_init(tsd);
    trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
    flow->session_state |= STREAM_STATE_SYN_ACK;

    trk.s_mgr.sub_state |= ( SUB_SYN_SENT | SUB_ACK_SENT );

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( trk.is_ack_valid(tsd.get_seg_ack() ) )
    {
        Flow* flow = tsd.get_flow();

        trk.update_tracker_ack_recv(tsd);
        trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
        flow->set_session_flags(SSNFLAG_ESTABLISHED);
        flow->session_state |= ( STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );
        session.update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    }

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( session.config->midstream_allowed(tsd.get_pkt()) )
    {
        session.update_session_on_ack( );
    }
    trk.s_mgr.sub_state |= SUB_ACK_SENT;

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( trk.is_ack_valid(tsd.get_seg_ack() ) )
    {
        trk.update_tracker_ack_recv(tsd);
        session.set_pkt_action_flag( trk.normalizer->handle_paws(tsd) );
        tsd.get_pkt()->packet_flags |= PKT_STREAM_TWH;
        session.update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    }

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.s_mgr.sub_state |= SUB_ACK_SENT;

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( trk.is_ack_valid(tsd.get_seg_ack() ) )
    {
        trk.update_tracker_ack_recv(tsd);
        tsd.get_pkt()->packet_flags |= PKT_STREAM_TWH;
        session.set_pkt_action_flag( trk.normalizer->handle_paws(tsd) );
        session.update_perf_base_state(TcpStreamTracker::TCP_ESTABLISHED);
        trk.set_tcp_state(TcpStreamTracker::TCP_ESTABLISHED);
    }

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.s_mgr.sub_state |= SUB_ACK_SENT;

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );
    if ( tsd.get_tcph()->is_ack() )
    {
        Flow* flow = tsd.get_flow();

        trk.update_tracker_ack_recv(tsd);
        session.set_pkt_action_flag( trk.normalizer->handle_paws(tsd) );
        flow->session_state |= STREAM_STATE_ACK;
        trk.set_tcp_state(TcpStreamTracker::TCP_CLOSE_WAIT);
    }

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk);
}

bool TcpStateSynRecv::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( trk.update_on_rst_recv(tsd) )
    {
        session.update_session_on_rst(tsd, false);
        session.update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        session.set_pkt_action_flag(ACTION_RST);
    }
    else
    {
        session.tel.set_tcp_event(EVENT_BAD_RST);
    }

    return default_state_action(tsd, trk);
}

