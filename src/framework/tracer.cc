//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// tracer.cc author Pranav Jain <ppramodj@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tracer.h"

#include "protocols/packet.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

std::string snort::TraceLoggerPlug::print_ntuple(const Packet* p)
{
    if ( !ntuple or !p or !p->ptrs.ip_api.is_valid() )
        return "";

    SfIpString src_addr;
    SfIpString dst_addr;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::stringstream ss;

    p->ptrs.ip_api.get_src()->ntop(src_addr);
    p->ptrs.ip_api.get_dst()->ntop(dst_addr);

    if ( p->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP) )
    {
        src_port = p->ptrs.sp;
        dst_port = p->ptrs.dp;
    }

    ss << src_addr << " " << src_port << " -> " << dst_addr << " " << dst_port << " ";
    ss << unsigned(p->get_ip_proto_next());
    ss << " AS=" << p->pkth->address_space_id;

    if (p->pkth->tenant_id)
        ss << " TN=" << p->pkth->tenant_id;

    // Delimits the header part and the trace message
    ss << " ";

    return ss.str();
}

std::string snort::TraceLoggerPlug::print_timestamp()
{
    if ( !timestamp )
        return "";

    char ts[TIMEBUF_SIZE];
    ts_print(nullptr, ts);

    return std::string(ts) + ":";
}

