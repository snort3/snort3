//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

// tcp_reassemblers.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 9, 2015

#ifndef TCP_REASSEMBLERS_H
#define TCP_REASSEMBLERS_H

#include "stream/tcp/tcp_reassembler.h"

class TcpReassemblerFactory
{
public:
    static TcpReassembler* create(TcpSession* session, TcpStreamTracker* tracker,
        StreamPolicy os_policy, bool server);
};

#endif

