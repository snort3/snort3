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
// ip.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ip.h"

#include "layer.h"

namespace snort
{
namespace ip
{
void IpApi::reset()
{
    type = IAT_NONE;
    iph = nullptr;
    src.clear();
    dst.clear();
}

void IpApi::set(const IP4Hdr* h4)
{
    iph = (const void*)h4;
    type = IAT_4;

    src.set(&h4->ip_src, AF_INET);
    dst.set(&h4->ip_dst, AF_INET);
}

void IpApi::set(const ip::IP6Hdr* h6)
{
    iph = (const void*)h6;
    type = IAT_6;

    src.set(&h6->ip6_src, AF_INET6);
    dst.set(&h6->ip6_dst, AF_INET6);
}

void IpApi::set(const SfIp& sip, const SfIp& dip)
{
    type = IAT_DATA;
    src.set(sip);
    dst.set(dip);
    iph = nullptr;
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

void IpApi::update(const SfIp& sip, const SfIp& dip)
{
    src.set(sip);
    dst.set(dip);
}

uint16_t IpApi::tos() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->tos();
    case IAT_6: return ((const IP6Hdr*)iph)->tos();
    default: break;
    }
    return 0;
}

uint8_t IpApi::ttl() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->ttl();
    case IAT_6: return ((const IP6Hdr*)iph)->hop_lim();
    default: break;
    }
    return 0;
}

/* This is different than the Packet's ip_proto_next field - this
 * variable hold the first non-ip and non-ipv6 extension protocols,
 * while proto() returns the next or proto() field of the raw IP
 * header */
IpProtocol IpApi::proto() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->proto();
    case IAT_6: return ((const IP6Hdr*)iph)->next();
    default: break;
    }
    return IpProtocol::PROTO_NOT_SET;
}

// header length field: datagram/payload-only length for 4/6
// you may want pay_len() or dgram_len() instead
uint16_t IpApi::raw_len() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->raw_len();
    case IAT_6: return ((const IP6Hdr*)iph)->raw_len();
    default: break;
    }
    return 0;
}

uint8_t IpApi::hlen() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->hlen();
    case IAT_6: return ((const IP6Hdr*)iph)->hlen();
    default: break;
    }
    return 0;
}

uint8_t IpApi::ver() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->ver();
    case IAT_6: return ((const IP6Hdr*)iph)->ver();
    default: break;
    }
    return 0;
}

bool operator==(const IpApi& lhs, const IpApi& rhs)
{
    if ( lhs.type != rhs.type )
        return false;

    // FIXIT-H is this really supposed to be a shallow compare?
    return ( lhs.iph == rhs.iph );
}

bool operator!=(const IpApi& lhs, const IpApi& rhs)
{ return !(lhs == rhs); }

uint32_t IpApi::id() const
{
    if ( type == IAT_4 )
        return (uint32_t)((const IP4Hdr*)iph)->id();

    if ( type != IAT_6 )
        return 0;

    const IP6Frag* const frag_hdr = layer::get_inner_ip6_frag();

    if (frag_hdr)
        return frag_hdr->id();

    return 0;
}

uint16_t IpApi::off() const
{
    if ( type == IAT_4 )
        return (uint32_t)((const IP4Hdr*)iph)->off();

    if ( type != IAT_6 )
        return 0;

    const IP6Frag* const frag_hdr = layer::get_inner_ip6_frag();

    if ( frag_hdr )
        return frag_hdr->off();

    return 0;
}

uint16_t IpApi::off_w_flags() const
{
    if ( type == IAT_4 )
        return (uint32_t)((const IP4Hdr*)iph)->off_w_flags();

    if ( type != IAT_6 )
        return 0;

    const IP6Frag* const frag_hdr = layer::get_inner_ip6_frag();

    if ( frag_hdr )
        return frag_hdr->off_w_flags();

    return 0;
}

const uint8_t* IpApi::ip_data() const
{
    switch ( type )
    {
    case IAT_4: return reinterpret_cast<const uint8_t*>(iph) + ((const IP4Hdr*)iph)->hlen();
    case IAT_6: return reinterpret_cast<const uint8_t*>(iph) + ((const IP6Hdr*)iph)->hlen();
    default: break;
    }
    return nullptr;
}

uint16_t IpApi::actual_ip_len() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->len();
    case IAT_6: return ((const IP6Hdr*)iph)->len();
    default: break;
    }
    return 0;
}

uint16_t IpApi::dgram_len() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->len();
    case IAT_6: return ((const IP6Hdr*)iph)->len() + IP6_HEADER_LEN;
    default: break;
    }
    return 0;
}

uint16_t IpApi::pay_len() const
{
    switch ( type )
    {
    case IAT_4: return ((const IP4Hdr*)iph)->len() - ((const IP4Hdr*)iph)->hlen();
    case IAT_6: return ((const IP6Hdr*)iph)->len();
    default: break;
    }
    return 0;
}

static inline bool is_loopback(uint32_t addr)
{ return (addr >> 24) == 0x7F; }

static bool is_loopback(const snort_in6_addr* const ip)
{
    const uint32_t* p = ip->u6_addr32;

    /* Check the first 64 bits in an IPv6 address, and
       verify they're zero.  If not, it's not a loopback */
    if (p[0] || p[1])
        return false;

    /* Check if the 3rd 32-bit int is zero */
    if ( p[2] == 0 )
    {
        /* ::7F00:0/104 is ipv4 compatible ipv6 */
        /* ::1 is the IPv6 loopback */
        return ( (ip->u6_addr8[12] == 0x7F) || (ntohl(p[3]) == 0x1) );
    }

    /* Check the 3rd 32-bit int for a mapped IPv4 address */
    if ( ntohl(p[2]) == 0xffff )
    {
        /* ::ffff:127.0.0.0/104 is IPv4 loopback mapped over IPv6 */
        return ( ip->u6_addr8[12] == 0x7F );
    }
    return false;
}

bool IpApi::is_src_loopback() const
{
    switch ( type )
    {
    case IAT_4: return is_loopback(ntohl(((const IP4Hdr*)iph)->get_src()));
    case IAT_6: return is_loopback(((const IP6Hdr*)iph)->get_src());
    default: break;
    }
    return false;
}

// true if the current source address ia the loopback address
bool IpApi::is_dst_loopback() const
{
    switch ( type )
    {
    case IAT_4: return ((ntohl(((const IP4Hdr*)iph)->get_dst())) >> 24) == 0x7F;
    case IAT_6: return is_loopback(((const IP6Hdr*)iph)->get_dst());
    default: break;
    }
    return false;
}
} // namespace ip
} // namespace snort

