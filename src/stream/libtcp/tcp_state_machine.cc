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

// tcp_state_machine.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 29, 2015

#include "tcp_stream_tracker.h"
#include "tcp_state_machine.h"

TcpStateMachine::TcpStateMachine(void)
{
    TcpStreamTracker::TcpState s;
    // register a default handler for each state...
    for ( s = TcpStreamTracker::TCP_LISTEN; s < TcpStreamTracker::TCP_MAX_STATES; s++ )
    {
        tcp_state_handlers[ s ] = nullptr;
        new TcpStateHandler(s, *this);
    }
}

TcpStateMachine::~TcpStateMachine(void)
{
    // TODO Auto-generated destructor stub
}

void TcpStateMachine::register_state_handler(TcpStreamTracker::TcpState state,
    TcpStateHandler& handler)
{
    if ( tcp_state_handlers[ state ] != nullptr )
        delete tcp_state_handlers[ state ];

    tcp_state_handlers[ state ] = &handler;
}

bool TcpStateMachine::eval(TcpSegmentDescriptor& tsd, TcpStreamTracker& tracker)
{
    tracker.set_tcp_event(tsd);
    return tcp_state_handlers[ tracker.get_tcp_state( ) ]->eval(tsd, tracker);
}

