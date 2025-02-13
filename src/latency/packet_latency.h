//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// packet_latency.h author Joel Cornett <jocornet@cisco.com>

#ifndef PACKET_LATENCY_H
#define PACKET_LATENCY_H

#include "main/snort_types.h"

namespace snort
{
struct Packet;
}

namespace packet_latency
{
    SO_PUBLIC bool force_enabled();

    SO_PUBLIC void set_force_enable(bool force);
}

class PacketLatency
{
public:
    static void push();
    static void pop(const snort::Packet*);
    static bool fastpath();

    static void tterm();

    class Context
    {
    public:
        Context(const snort::Packet* p) : p(p) { PacketLatency::push(); }
        ~Context() { PacketLatency::pop(p); }

    private:
        const snort::Packet* p;
    };
};

#endif
