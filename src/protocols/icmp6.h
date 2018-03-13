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
// icmp6.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_ICMP6_H
#define PROTOCOLS_ICMP6_H

#include <cstdint>

namespace snort
{
namespace icmp
{
constexpr uint16_t ICMP6_HEADER_MIN_LEN = 4;
constexpr uint16_t ICMP6_HEADER_NORMAL_LEN = 8;

//enum class Icmp6Types : std::uint8_t
enum Icmp6Types : std::uint8_t
{
    DESTINATION_UNREACHABLE = 1,
    PACKET_TOO_BIG = 2,
    TIME_EXCEEDED6 = 3,
    PARAMETER_PROBLEM = 4,
    ECHO_REQUEST = 128,
    ECHO_REPLY = 129,
    MULTICAST_LISTENER_QUERY = 130,
    MULTICAST_LISTENER_REPORT = 131,
    MULTICAST_LISTENER_DONE = 132,
    ROUTER_SOLICITATION = 133,
    ROUTER_ADVERTISEMENT = 134,
    NEIGHBOR_SOLICITATION = 135,
    NEIGHBOR_ADVERTISEMENT = 136,
    REDIRECT6 = 137,
    NODE_INFORMATION_QUERY = 139,
    NODE_INFORMATION_RESPONSE = 140,
    INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION = 141,
    INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT = 142,
    VERSION_2_MULTICAST_LISTENER_REPORT = 143,
    HOME_AGENT_ADDRESS_DISCOVERY_REQUEST = 144,
    HOME_AGENT_ADDRESS_DISCOVERY_REPLY = 145,
    MOBILE_PREFIX_SOLICITATION = 146,
    MOBILE_PREFIX_ADVERTISEMENT = 147,
    CERTIFICATION_PATH_SOLICITATION = 148,
    CERTIFICATION_PATH_ADVERTISEMENT = 149,
    MULTICAST_ROUTER_ADVERTISEMENT = 151,
    MULTICAST_ROUTER_SOLICITATION = 152,
    MULTICAST_ROUTER_TERMINATION = 153,
    FMIPV6 = 154,
    RPL_CONTROL = 155,
    ILNPV6_LOCATOR_UPDATE = 156,
    DUPLICATE_ADDRESS_REQUEST = 157,
    DUPLICATE_ADDRESS_CONFIRMATION = 158,
    MPL_CONTROL = 159
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
}  // namespace icmp
}  // namespace snort

#endif

