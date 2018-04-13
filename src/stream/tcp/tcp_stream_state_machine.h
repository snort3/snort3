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

// tcp_stream_state_machine.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Apr 1, 2016

#ifndef TCP_STREAM_STATE_MACHINE_H
#define TCP_STREAM_STATE_MACHINE_H

#include "stream/libtcp/tcp_state_machine.h"

class TcpStreamStateMachine: public TcpStateMachine
{
public:
    static TcpStateMachine* get_instance( )
    {
        static TcpStreamStateMachine tsm;
        return &tsm;
    }

private:
    TcpStreamStateMachine();

};
#endif

