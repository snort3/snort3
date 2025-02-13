//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// eth.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_ETH_H
#define PROTOCOLS_ETH_H

#include <string>

#include <arpa/inet.h>
#include "protocols/protocol_ids.h"

#define ETHERNET_HEADER_LEN 14
#define ETHERNET_MTU        1500

namespace snort
{
namespace eth
{
constexpr uint16_t MTU_LEN = 1500;
constexpr uint16_t MAX_FRAME_LENGTH = 1500;
constexpr uint16_t ETH_HEADER_LEN = 14;

struct EtherHdr
{
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;

    /* return data in host byte order */
    inline ProtocolId ethertype() const
    { return (ProtocolId)ntohs(ether_type); }

    /* return data in network order */
    inline uint16_t raw_ethertype() const
    { return ether_type; }

    // <Src MAC> -> <Dst Mac> <Ether Type>
    std::string to_string() const
    {
        char str[50];

        snprintf(str, sizeof(str),
            "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X %04X",
            ether_src[0], ether_src[1], ether_src[2],
            ether_src[3], ether_src[4], ether_src[5],
            ether_dst[0], ether_dst[1], ether_dst[2],
            ether_dst[3], ether_dst[4], ether_dst[5],
            (uint16_t)ethertype());

        return str;
    }
};
} // namespace eth
} // namespace snort

#endif

