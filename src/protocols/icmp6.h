//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// icmp6.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_ICMP6_H
#define PROTOCOLS_ICMP6_H

#include <cstdint>

namespace icmp
{
constexpr uint16_t ICMP6_HEADER_MIN_LEN = 4;
constexpr uint16_t ICMP6_HEADER_NORMAL_LEN = 8;

//enum class Icmp6Types : std::uint8_t
enum Icmp6Types : std::uint8_t
{
    UNREACH = 1,
    BIG = 2,
    TIME = 3,
    PARAMS = 4,
    ECHO_6 = 128,
    REPLY_6 = 129,
    SOLICITATION = 133,
    ADVERTISEMENT = 134,
    NODE_INFO_QUERY = 139,
    NODE_INFO_RESPONSE = 140,
};

enum class Icmp6Code : std::uint8_t
{
    /* Type == 1 */
    UNREACH_NET = 0x00,
    UNREACH_FILTER_PROHIB = 0x01,
    UNREACH_INVALID = 0x02,
    UNREACH_HOST = 0x03,
    UNREACH_PORT = 0x04,

    /* Type == ADVERTISEMENT */
    ADVERTISEMENT = 0X00,
};

struct Icmp6Hdr
{
    Icmp6Types type;
    Icmp6Code code;
    uint16_t csum;

    union
    {
        uint32_t opt32;
        uint16_t opt16[2];
        uint8_t opt8[4];
    };
};

struct ICMP6TooBig
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint32_t mtu;
};

struct ICMP6RouterAdvertisement
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint8_t num_addrs;
    uint8_t addr_entry_size;
    uint16_t lifetime;
    uint32_t reachable_time;
    uint32_t retrans_time;
};

struct ICMP6RouterSolicitation
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint32_t reserved;
};

struct ICMP6NodeInfo
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint16_t qtype;
    uint16_t flags;
    uint64_t nonce;
};
}  // namespace icmp6

#endif

