//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_trace.h author Oleksii Khomiakovskyi <okhomiak@cisco.com>

#ifndef TCP_TRACE_H
#define TCP_TRACE_H

#include "main/thread.h"

namespace snort
{
struct Packet;
}

class TcpSegmentDescriptor;

enum
{
    TRACE_SEGMENTS = 0,
    TRACE_STATE,
};

void S5TraceTCP(const TcpSegmentDescriptor&, const snort::Packet*);

#endif

