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

void IpApi::set(const IPHdr* h4)
{
    ip4h = h4;
    ip6h = nullptr;
    src_p = nullptr;
    dst_p = nullptr;
}

void IpApi::set(const ipv6::IP6RawHdr* h6)
{
    ip6h = h6;
    ip4h = nullptr;
    src_p = nullptr;
    dst_p = nullptr;
}

bool IpApi::set(const uint8_t* raw_ip_data)
{
    const IPHdr* h4 = reinterpret_cast<const IPHdr*>(raw_ip_data);
    if (h4->get_ver() == 4)
    {
        set(h4);
        return true;
    }

    const ipv6::IP6RawHdr* h6 =
        reinterpret_cast<const ipv6::IP6RawHdr*>(raw_ip_data);

    if (h6->get_ver() != 6)
        return false;

    set(h6);
    return true;
}

const sfip_t *IpApi::get_src()
{
    if (src_p)
        return src_p;

    if(ip4h)
    {
        src.family = AF_INET;
        src.bits = 32;

        // TODO:  Make this a pointer rather than copying
        //          will likely need to change Snort++
        src.ip32[0] = *(uint32_t*)(&ip4h->ip_src);
        std::memset(&(src.ip32[1]), 0, 12);
    }
    else if (ip6h)
    {
        src.family = AF_INET6;
        src.bits = 128;

        std::memcpy(&(src.ip8), &(ip6h->ip6_src), 16);
    }
    else
    {
        return nullptr;
    }

    src_p = &src;
    return src_p;
}


const sfip_t *IpApi::get_dst()
{
    if (dst_p)
        return dst_p;

    if(ip4h)
    {
        dst.family = AF_INET;
        dst.bits = 32;

        // TODO:  Make this a pointer rather than copying
        //          will likely need to change Snort++
        dst.ip32[0] = *(uint32_t*)(&ip4h->ip_dst);
        std::memset(&(dst.ip32[1]), 0, 12);
    }
    else if (ip6h)
    {
        dst.family = AF_INET6;
        dst.bits = 128;
        std::memcpy(&(dst.ip8), &(ip6h->ip6_dst), 16);
    }
    else
    {
        return nullptr;
    }

    dst_p = &dst;
    return dst_p;

}

uint32_t IpApi::id(const Packet* const p) const
{
    if (ip4h)
        return ip4h->get_id();

    // ensure we have an ipv6 frag
    if (p->ip6_extension_count == 0 || p->ip_frag_start == 0 || !ip6h )
        return 0;

    const IP6Frag* const frag_hdr = reinterpret_cast<const IP6Frag* const>(
            p->ip6_extensions[p->ip6_frag_index].data);

    return frag_hdr->get_id();
}

uint16_t IpApi::off(const Packet* const p) const
{
    if (ip4h)
        return ip4h->get_id();

    // ensure we have an ipv6 frag
    if (p->ip6_extension_count == 0 || p->ip_frag_start == 0 || !ip6h)
        return 0;

    const IP6Frag* const frag_hdr = reinterpret_cast<const IP6Frag* const>(
            p->ip6_extensions[p->ip6_frag_index].data);

    return frag_hdr->get_off();
}


const uint8_t* IpApi::ip_data() const
{
    if (ip4h)
        return reinterpret_cast<const uint8_t*>(ip4h) + (ip4h->get_hlen() << 2);

    if (ip6h)
        return reinterpret_cast<const uint8_t*>(ip6h) + (ip6h->get_hlen() << 2);

    return nullptr;
}

uint16_t IpApi::actual_ip_len() const
{
    if (ip4h)
        return ntohs(ip4h->get_len());

    if (ip6h)
        return ntohs(ip6h->get_len());

    return 0;
}

uint16_t IpApi::dgram_len() const
{
    if (ip4h)
        return ntohs(ip4h->get_len());

    if (ip6h)
        return ntohs(ip6h->get_len()) + (ip6h->get_hlen() << 2);

    return 0;
}

uint16_t IpApi::pay_len() const
{
    if (ip4h)
        return ntohs(ip4h->get_len()) - (ip4h->get_hlen() << 2);

    if (ip6h)
        return ntohs(ip6h->get_len());

    return 0;
}

} // namespace ip
