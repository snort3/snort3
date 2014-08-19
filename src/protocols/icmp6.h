/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// icmp6.h author Josh Rosenbaum <jrosenba@cisco.com>


#ifndef PROTOCOLS_ICMP6_H
#define PROTOCOLS_ICMP6_H

#include <cstdint>

namespace icmp
{


constexpr uint16_t ICMP6_HEADER_MIN_LEN = 4;
constexpr uint16_t ICMP6_HEADER_NORMAL_LEN = 8;


struct ICMP6Hdr
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;

};

struct ICMP6TooBig
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint32_t mtu;
} ;

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
} ;

struct ICMP6NodeInfo
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint16_t qtype;
    uint16_t flags;
    uint64_t nonce;
} ;


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
    UNREACH_HOST = 0x03,
    UNREACH_PORT = 0x04,
};

}  // namespace icmp6


#endif

