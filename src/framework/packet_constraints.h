//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// packet_constraints.h author Serhii Lysenko <selysenk@cisco.com>

#ifndef PACKET_CONSTRAINTS_H
#define PACKET_CONSTRAINTS_H

#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"

namespace snort
{

class Flow;
struct Packet;

struct PacketConstraints
{
    enum SetBits : uint8_t {
        IP_PROTO = 1,
        SRC_IP   = 1 << 1,
        DST_IP   = 1 << 2,
        SRC_PORT = 1 << 3,
        DST_PORT = 1 << 4,
    };

    bool operator==(const PacketConstraints& other) const;

    bool packet_match(const Packet& p) const;
    bool flow_match(const Flow& f) const;

    IpProtocol ip_proto = IpProtocol::PROTO_NOT_SET;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    snort::SfIp src_ip;
    snort::SfIp dst_ip;

    uint8_t set_bits = 0;

    bool match = true;
};

} // namespace snort

#endif

