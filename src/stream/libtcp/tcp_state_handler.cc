//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_state_handler.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jun 24, 2015

#include <iostream>
using namespace std;

#include "tcp_state_handler.h"

TcpStateHandler::TcpStateHandler()
{
    // TODO Auto-generated constructor stub

}

TcpStateHandler::~TcpStateHandler()
{
    // TODO Auto-generated destructor stub

}
void TcpStateHandler::eval( TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker )
{
    TcpStateMachine::TcpEvents tcp_event = TcpStateMachine::TCP_MAX_EVENTS;

    switch( tcp_event )
    {
    case TcpStateMachine::TCP_SYN_SENT_EVENT:
        syn_sent( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_SYN_RECV_EVENT:
        syn_recv( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_SYN_ACK_SENT_EVENT:
        syn_ack_sent( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_SYN_ACK_RECV_EVENT:
        syn_ack_recv( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_ACK_SENT_EVENT:
        ack_sent( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_ACK_RECV_EVENT:
        ack_recv( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_DATA_SEG_SENT_EVENT:
        data_seg_sent( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_DATA_SEG_RECV_EVENT:
        data_seg_recv( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_FIN_SENT_EVENT:
        fin_sent( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_FIN_RECV_EVENT:
        fin_recv( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_RST_SENT_EVENT:
        rst_sent( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_RST_RECV_EVENT:
        rst_recv( tcp_seg, tracker );
        break;

    case TcpStateMachine::TCP_MAX_EVENTS:
    default:
        cout << "Invalid Tcp Event " << tcp_event << endl;
        break;

    }
}

void TcpStateHandler::default_state_action( TcpSegmentDescriptor* tcp_seg, TcpStreamTracker* tracker, const char* func_name )
{
    cout << "Default Implementation of " << func_name << "tcp_seg: " << tcp_seg << "tracker: " << tracker << endl;
}

void TcpStateHandler::syn_sent( TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker )
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::syn_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::syn_ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::syn_ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::ack_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::ack_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::data_seg_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::data_seg_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::fin_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::fin_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::rst_sent(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

void TcpStateHandler::rst_recv(TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker)
{
    default_state_action( &tcp_seg, &tracker, __func__ );
}

