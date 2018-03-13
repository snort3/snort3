//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

    /* return data in byte order */
    inline ProtocolId ethertype() const
    { return (ProtocolId)ntohs(ether_type); }

    /* return data in network order */
    inline uint16_t raw_ethertype() const
    { return ether_type; }
};
} // namespace eth
} // namespace snort

#endif

