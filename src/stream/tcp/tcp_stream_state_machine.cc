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

// tcp_stream_state_machine.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Apr 1, 2016

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_stream_state_machine.h"

#include "tcp_state_none.h"
#include "tcp_state_closed.h"
#include "tcp_state_listen.h"
#include "tcp_state_syn_sent.h"
#include "tcp_state_syn_recv.h"
#include "tcp_state_established.h"
#include "tcp_state_close_wait.h"
#include "tcp_state_closing.h"
#include "tcp_state_fin_wait1.h"
#include "tcp_state_fin_wait2.h"
#include "tcp_state_last_ack.h"
#include "tcp_state_time_wait.h"

TcpStreamStateMachine::TcpStreamStateMachine()
{
    // initialize stream tracker state machine with handler for each state...
    new TcpStateNone(*this);
    new TcpStateClosed(*this);
    new TcpStateListen(*this);
    new TcpStateSynSent(*this);
    new TcpStateSynRecv(*this);
    new TcpStateEstablished(*this);
    new TcpStateFinWait1(*this);
    new TcpStateFinWait2(*this);
    new TcpStateClosing(*this);
    new TcpStateCloseWait(*this);
    new TcpStateLastAck(*this);
    new TcpStateTimeWait(*this);
}

