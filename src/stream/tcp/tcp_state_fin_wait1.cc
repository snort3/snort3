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

// tcp_state_fin_wait1.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Aug 5, 2015

#include <iostream>
using namespace std;

#include "tcp_module.h"
#include "tcp_tracker.h"
#include "tcp_session.h"
#include "tcp_normalizer.h"
#include "tcp_state_fin_wait1.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

TcpStateFinWait1::TcpStateFinWait1(TcpStateMachine& tsm, TcpSession& ssn) :
    TcpStateHandler(TcpStreamTracker::TCP_FIN_WAIT1, tsm), session(ssn)
{
}

TcpStateFinWait1::~TcpStateFinWait1()
{
}

bool TcpStateFinWait1::syn_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.s_mgr.sub_state |= SUB_SYN_SENT;

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::syn_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.normalizer->ecn_tracker(tsd.get_tcph(), session.config->require_3whs() );
    if ( tsd.get_seg_len() )
        session.handle_data_on_syn(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.s_mgr.sub_state |= ( SUB_SYN_SENT | SUB_ACK_SENT );

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::syn_ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_sent(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::ack_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_recv(tsd);
    check_for_window_slam(tsd, trk);

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::data_seg_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_sent(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::data_seg_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_recv(tsd);
    check_for_window_slam(tsd, trk);

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::fin_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_sent(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::fin_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    trk.update_tracker_ack_recv(tsd);

    if ( check_for_window_slam(tsd, trk) )
        session.handle_fin_recv_in_fw1(tsd);

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::rst_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::rst_recv(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    auto& trk = static_cast< TcpTracker& >( tracker );

    if ( trk.update_on_rst_recv(tsd) )
    {
        session.update_session_on_rst(tsd, true);
        session.update_perf_base_state(TcpStreamTracker::TCP_CLOSING);
        session.set_pkt_action_flag(ACTION_RST);
    }
    else
    {
        session.tel.set_tcp_event(EVENT_BAD_RST);
    }

    return default_state_action(tsd, trk);
}

bool TcpStateFinWait1::check_for_window_slam(TcpSegmentDescriptor& tsd, TcpTracker& trk)
{
    DebugFormat(DEBUG_STREAM_STATE, "tsd.ack %X >= listener->snd_nxt %X\n",
        tsd.get_seg_ack(), trk.get_snd_nxt());

    if ( SEQ_EQ(tsd.get_seg_ack(), trk.get_snd_nxt() ) )
    {
        if ( (trk.normalizer->get_os_policy() == StreamPolicy::OS_WINDOWS)
            && (tsd.get_seg_wnd() == 0))
        {
            session.tel.set_tcp_event(EVENT_WINDOW_SLAM);
            inc_tcp_discards();

            if (trk.normalizer->packet_dropper(tsd, NORM_TCP_BLOCK))
            {
                session.set_pkt_action_flag(ACTION_BAD_PKT);
                return false;
            }
        }

        trk.set_tcp_state(TcpStreamTracker::TCP_FIN_WAIT2);

        if ( trk.s_mgr.state_queue == TcpStreamTracker::TCP_CLOSING )
        {
            trk.s_mgr.state_queue = TcpStreamTracker::TCP_TIME_WAIT;
            trk.s_mgr.transition_seq = tsd.get_end_seq();
            trk.s_mgr.expected_flags = TH_ACK;
        }
    }

    return true;
}

