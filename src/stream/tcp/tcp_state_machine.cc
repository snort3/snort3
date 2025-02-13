//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "tcp_session.h"
#include "tcp_state_none.h"
#include "tcp_state_closed.h"
#include "tcp_state_listen.h"
#include "tcp_state_syn_sent.h"
#include "tcp_state_syn_recv.h"
#include "tcp_state_mid_stream_sent.h"
#include "tcp_state_mid_stream_recv.h"
#include "tcp_state_established.h"
#include "tcp_state_close_wait.h"
#include "tcp_state_closing.h"
#include "tcp_state_fin_wait1.h"
#include "tcp_state_fin_wait2.h"
#include "tcp_state_last_ack.h"
#include "tcp_state_time_wait.h"

TcpStateMachine* TcpStateMachine::tsm = nullptr;

TcpStateMachine* TcpStateMachine::initialize()
{
    assert(!tsm);
    TcpStateMachine::tsm = new TcpStateMachine();
    return TcpStateMachine::tsm;
}

void TcpStateMachine::term()
{
    delete TcpStateMachine::tsm;
    TcpStateMachine::tsm = nullptr;
}

TcpStateMachine::TcpStateMachine()
{
    for ( auto s = TcpStreamTracker::TCP_LISTEN; s < TcpStreamTracker::TCP_MAX_STATES; s++ )
        tcp_state_handlers[ s ] = nullptr;

    // initialize stream tracker state machine with handler for each state...
    new TcpStateNone(*this);
    new TcpStateClosed(*this);
    new TcpStateListen(*this);
    new TcpStateSynSent(*this);
    new TcpStateSynRecv(*this);
    new TcpStateMidStreamSent(*this);
    new TcpStateMidStreamRecv(*this);
    new TcpStateEstablished(*this);
    new TcpStateFinWait1(*this);
    new TcpStateFinWait2(*this);
    new TcpStateClosing(*this);
    new TcpStateCloseWait(*this);
    new TcpStateLastAck(*this);
    new TcpStateTimeWait(*this);
}

TcpStateMachine::~TcpStateMachine()
{
    for ( auto s = TcpStreamTracker::TCP_LISTEN; s < TcpStreamTracker::TCP_MAX_STATES; s++ )
        delete tcp_state_handlers[ s ];
}

void TcpStateMachine::register_state_handler(TcpStreamTracker::TcpState state,
    TcpStateHandler& handler)
{
    assert( !tcp_state_handlers[ state ]);
    tcp_state_handlers[ state ] = &handler;
}

bool TcpStateMachine::eval(TcpSegmentDescriptor& tsd)
{
    TcpStreamTracker* talker = tsd.get_talker();
    const TcpStreamTracker::TcpState talker_state = talker->get_tcp_state();

    talker->set_tcp_event(tsd);
    if ( tcp_state_handlers[ talker_state ]->do_pre_sm_packet_actions(tsd, *talker) )
    {
        if ( tcp_state_handlers[ talker_state ]->eval(tsd, *talker) )
        {
            TcpStreamTracker* listener = tsd.get_listener();
            const TcpStreamTracker::TcpState listener_state = listener->get_tcp_state( );
            listener->set_tcp_event(tsd);
            tcp_state_handlers[ listener_state ]->eval(tsd, *listener);
            tcp_state_handlers[ listener_state ]->do_post_sm_packet_actions(tsd, *listener);
            return true;
        }
        else
            talker->session->check_for_pseudo_established(tsd.get_pkt());

        return false;
    }

    return false;
}

