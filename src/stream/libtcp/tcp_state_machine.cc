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

// tcp_state_machine.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 29, 2015

#include "tcp_state_machine.h"

const char* tcp_state_names[] =
{ "TCP_LISTEN", "TCP_SYN_SENT", "TCP_SYN_RECV", "TCP_ESTABLISHED","TCP_FIN_WAIT1",
  "TCP_FIN_WAIT2", "TCP_CLOSE_WAIT", "TCP_CLOSING", "TCP_LAST_ACK",
  "TCP_TIME_WAIT", "TCP_CLOSED"
};

const char *tcp_event_names[] = { "TCP_SYN_SENT_EVENT", "TCP_SYN_RECV_EVENT",
        "TCP_SYN_ACK_SENT_EVENT", "TCP_SYN_ACK_RECV_EVENT", "TCP_ACK_SENT_EVENT",
        "TCP_ACK_RECV_EVENT", "TCP_DATA_SEG_SENT_EVENT", "TCP_DATA_SEG_RECV_EVENT",
        "TCP_FIN_SENT_EVENT", "TCP_FIN_RECV_EVENT", "TCP_RST_SENT_EVENT", "TCP_RST_RECV_EVENT" };


TcpStateMachine::~TcpStateMachine()
{
    // TODO Auto-generated destructor stub
}
TcpStateMachine::TcpStateMachine()
{
    // TODO Auto-generated constructor stub

}

void TcpStateMachine::eval( TcpSegmentDescriptor &tcp_seg, TcpStreamTracker &tracker )
{
    tracker.set_tcp_event( tcp_seg, tracker.is_client_tracker( ) );
    tcp_state_handlers[ tracker.get_tcp_state( ) ]->eval( tcp_seg, tracker );
}
