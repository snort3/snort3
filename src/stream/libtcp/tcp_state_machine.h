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

// tcp_state_machine.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 29, 2015

#ifndef TCP_STATE_MACHINE_H
#define TCP_STATE_MACHINE_H

#include "stream/libtcp/tcp_state_handler.h"
#include "stream/libtcp/tcp_stream_tracker.h"
#include "stream/libtcp/tcp_segment_descriptor.h"

class TcpStateMachine
{
public:
    virtual ~TcpStateMachine();

    virtual void register_state_handler(TcpStreamTracker::TcpState, TcpStateHandler&);
    virtual bool eval(TcpSegmentDescriptor&, TcpStreamTracker&, TcpStreamTracker&);

protected:
    TcpStateMachine();

    TcpStateHandler* tcp_state_handlers[ TcpStreamTracker::TCP_MAX_STATES ];
};

#endif

