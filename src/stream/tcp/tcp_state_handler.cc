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

// tcp_state_handler.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jun 24, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_handler.h"

#include <iostream>

#include "tcp_state_machine.h"

using namespace std;

TcpStateHandler::TcpStateHandler(TcpStreamTracker::TcpState state, TcpStateMachine& tsm)
{ tsm.register_state_handler(state, *this); }

bool TcpStateHandler::do_pre_sm_packet_actions(TcpSegmentDescriptor&, TcpStreamTracker&)
{  return true; }

bool TcpStateHandler::do_post_sm_packet_actions(TcpSegmentDescriptor&, TcpStreamTracker&)
{ return true; }

bool TcpStateHandler::eval(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    switch ( tracker.get_tcp_event() )
    {
    case TcpStreamTracker::TCP_SYN_SENT_EVENT:
        return syn_sent(tsd, tracker);

    case TcpStreamTracker::TCP_SYN_RECV_EVENT:
        return syn_recv(tsd, tracker);

    case TcpStreamTracker::TCP_SYN_ACK_SENT_EVENT:
        return syn_ack_sent(tsd, tracker);

    case TcpStreamTracker::TCP_SYN_ACK_RECV_EVENT:
        return syn_ack_recv(tsd, tracker);

    case TcpStreamTracker::TCP_ACK_SENT_EVENT:
        return ack_sent(tsd, tracker);

    case TcpStreamTracker::TCP_ACK_RECV_EVENT:
        return ack_recv(tsd, tracker);

    case TcpStreamTracker::TCP_DATA_SEG_SENT_EVENT:
        return data_seg_sent(tsd, tracker);

    case TcpStreamTracker::TCP_DATA_SEG_RECV_EVENT:
        return data_seg_recv(tsd, tracker);

    case TcpStreamTracker::TCP_FIN_SENT_EVENT:
        return fin_sent(tsd, tracker);

    case TcpStreamTracker::TCP_FIN_RECV_EVENT:
        return fin_recv(tsd, tracker);

    case TcpStreamTracker::TCP_RST_SENT_EVENT:
        return rst_sent(tsd, tracker);

    case TcpStreamTracker::TCP_RST_RECV_EVENT:
        return rst_recv(tsd, tracker);

    case TcpStreamTracker::TCP_NO_FLAGS_EVENT:
        return no_flags(tsd, tracker);

    default:
        break;
    }

    assert(false);
    return false;
}

