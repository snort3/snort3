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

// tcp_state_machine.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 29, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_state_machine.h"

TcpStateMachine::TcpStateMachine()
{
    for ( auto s = TcpStreamTracker::TCP_LISTEN; s < TcpStreamTracker::TCP_MAX_STATES; s++ )
        tcp_state_handlers[ s ] = nullptr;
}

TcpStateMachine::~TcpStateMachine()
{
    for ( auto s = TcpStreamTracker::TCP_LISTEN; s < TcpStreamTracker::TCP_MAX_STATES; s++ )
        delete tcp_state_handlers[ s ];
}

void TcpStateMachine::register_state_handler(TcpStreamTracker::TcpState state,
    TcpStateHandler& handler)
{
    delete tcp_state_handlers[ state ];
    tcp_state_handlers[ state ] = &handler;
}

bool TcpStateMachine::eval(TcpSegmentDescriptor& tsd, TcpStreamTracker& talker,
    TcpStreamTracker& listener)
{
    TcpStreamTracker::TcpState tcp_state = talker.get_tcp_state( );

    talker.set_tcp_event(tsd);
    if ( tcp_state_handlers[ tcp_state ]->do_pre_sm_packet_actions(tsd, talker) )
    {
        if ( tcp_state_handlers[ tcp_state ]->eval(tsd, talker) )
        {
            tcp_state = listener.get_tcp_state( );
            listener.set_tcp_event(tsd);
            tcp_state_handlers[ tcp_state ]->eval(tsd, listener);
            tcp_state_handlers[ tcp_state ]->do_post_sm_packet_actions(tsd, listener);
            return true;
        }

        return false;
    }

    return false;
}

