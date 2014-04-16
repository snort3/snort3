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


#ifndef ICMP6_H
#define ICMP6_H

#include <cstdint>

namespace icmp6
{

namespace detail
{
    const uint16_t HEADER_MIN_LEN = 4;
    const uint16_t HEADER_NORMAL_LEN = 8;
} // namespace detail

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

//
//enum class Icmp6Types : std::uint8_t {
enum Icmp6Types : std::uint8_t   {
    UNREACH = 1,
    ICMP6_TYPE_BIG = 2,
    TIME = 3,
    PARAMS = 4,
    ECHO = 128,
    REPLY = 129,
    SOLICITATION = 133,
    ADVERTISEMENT = 134,
    NODE_INFO_QUERY = 139,
    NODE_INFO_RESPONSE = 140,
};

inline uint16_t hdr_min_len()
{
    return detail::HEADER_MIN_LEN;
}


inline uint16_t hdr_normal_len()
{
    return detail::HEADER_NORMAL_LEN;
}

}  // namespace icmp6



//   Things that should be deleted immediately....which I bet will manage to make it into production

#define ICMP6_UNREACH 1
#define ICMP6_BIG    2
#define ICMP6_TIME   3
#define ICMP6_PARAMS 4
#define ICMP6_ECHO   128
#define ICMP6_REPLY  129
#define ICMP6_SOLICITATION 133
#define ICMP6_ADVERTISEMENT 134
#define ICMP6_NODE_INFO_QUERY 139
#define ICMP6_NODE_INFO_RESPONSE 140

typedef icmp6::ICMP6Hdr ICMP6Hdr;
typedef icmp6::ICMP6TooBig ICMP6TooBig;
typedef icmp6::ICMP6NodeInfo ICMP6NodeInfo;
typedef icmp6::ICMP6RouterAdvertisement ICMP6RouterAdvertisement;
typedef icmp6::ICMP6RouterSolicitation ICMP6RouterSolicitation;


#endif

