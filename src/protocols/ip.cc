/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2007-2013 Sourcefire, Inc.
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
// ip.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <arpa/inet.h>
#include "protocols/ip.h"
#include "protocols/packet.h"

namespace ip
{

void IpApi::reset()
{
    ip4h = nullptr;
    ip6h = nullptr;
    src_p = nullptr;
    dst_p = nullptr;
}

void IpApi::set(const IP4Hdr* h4)
{
    ip4h = h4;
    ip6h = nullptr;

    src.family = AF_INET;
    src.bits = 32;
    src.ip32[0] = *(uint32_t*)(&ip4h->ip_src);
    std::memset(&(src.ip32[1]), 0, 12);
    src_p = &src;

    dst.family = AF_INET;
    dst.bits = 32;
    dst.ip32[0] = *(uint32_t*)(&ip4h->ip_dst);
    std::memset(&(dst.ip32[1]), 0, 12);
    dst_p = &dst;
}

void IpApi::set(const ip::IP6Hdr* h6)
{
    ip6h = h6;
    ip4h = nullptr;

    src.family = AF_INET6;
    src.bits = 128;
    std::memcpy(&(src.ip8), &(ip6h->ip6_src), 16);
    src_p = &src;

    dst.family = AF_INET6;
    dst.bits = 128;
    std::memcpy(&(dst.ip8), &(ip6h->ip6_dst), 16);
    dst_p = &dst;
}

bool IpApi::set(const uint8_t* raw_ip_data)
{
    const IP4Hdr* h4 = reinterpret_cast<const IP4Hdr*>(raw_ip_data);
    if (h4->ver() == 4)
    {
        set(h4);
        return true;
    }

    const IP6Hdr* h6 = reinterpret_cast<const IP6Hdr*>(raw_ip_data);

    if (h6->ver() == 6)
    {
        set(h6);
        return true;
    }

    return false;
}

uint32_t IpApi::id() const
{
    if (ip4h)
        return (uint32_t)ip4h->id();

    const IP6Frag* const frag_hdr = layer::get_inner_ip6_frag();

    if (frag_hdr)
        return frag_hdr->id();
    return 0;
}

uint16_t IpApi::off() const
{
    if (ip4h)
        return ip4h->off();

    const IP6Frag* const frag_hdr = layer::get_inner_ip6_frag();

    if (frag_hdr)
        return frag_hdr->off();
    return 0;
}

uint16_t IpApi::off_w_flags() const
{
    if (ip4h)
        return ip4h->off_w_flags();

    const IP6Frag* const frag_hdr = layer::get_inner_ip6_frag();

    if (frag_hdr)
        return frag_hdr->off_w_flags();
    return 0;
}

const uint8_t* IpApi::ip_data() const
{
    if (ip4h)
        return reinterpret_cast<const uint8_t*>(ip4h) + ip4h->hlen();

    if (ip6h)
        return reinterpret_cast<const uint8_t*>(ip6h) + ip6h->hlen();

    return nullptr;
}

uint16_t IpApi::actual_ip_len() const
{
    if (ip4h)
        return ip4h->len();

    if (ip6h)
        return ip6h->len();

    return 0;
}

uint16_t IpApi::dgram_len() const
{
    if (ip4h)
        return ip4h->len();

    if (ip6h)
        return ip6h->len() + IP6_HEADER_LEN;

    return 0;
}

uint16_t IpApi::pay_len() const
{
    if (ip4h)
        return ip4h->len() - ip4h->hlen();

    if (ip6h)
        return ip6h->len();

    return 0;
}

static bool is_ip6_loopback(const snort_in6_addr* const ip)
{
    const uint32_t* p = ip->u6_addr32;

    /* Check the first 64 bits in an IPv6 address, and */
    /* verify they're zero.  If not, it's not a loopback */
    if(p[0] || p[1])
        return false;

    /* Check if the 3rd 32-bit int is zero */
    if ( p[2] == 0 ) {
        /* ::7f00:0/104 is ipv4 compatible ipv6 */
        /* ::1 is the IPv6 loopback */
        return ( (ip->u6_addr8[12] == 0x7f) || (ntohl(p[3]) == 0x1) );
    }

    /* Check the 3rd 32-bit int for a mapped IPv4 address */
    if ( ntohl(p[2]) == 0xffff ) {
        /* ::ffff:127.0.0.0/104 is IPv4 loopback mapped over IPv6 */
        return ( ip->u6_addr8[12] == 0x7f );
    }
    return false;
}

bool IpApi::is_src_loopback() const
{
    if (ip4h)
        return ((ntohl(ip4h->get_src())) >> 24) == 0x7f;

    if (ip6h)
        return is_ip6_loopback(ip6h->get_src());

    return false;
}

    // true if the current source address ia the loopback address
bool IpApi::is_dst_loopback() const
{
    if (ip4h)
        return ((ntohl(ip4h->get_dst())) >> 24) == 0x7f;

    if (ip6h)
        return is_ip6_loopback(ip6h->get_dst());

    return false;
}


} // namespace ip
