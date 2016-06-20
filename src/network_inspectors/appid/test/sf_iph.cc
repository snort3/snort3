/* $Id: sf_iph.c,v 1.2 2015/03/25 14:45:18 andrbake Exp $ */
/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#include <string.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "decode.h"

#define FAILURE -1
#define SUCCESS 0
#define IP6_HEADER_LEN 40

/* Version is the first four bits of the uint32_t passed in */
#define IP6_VER(x) \
    (ntohl(x) >> 28)

/* The 'Packet' structure is almost always allocated on the stack.
 * Likewise, return buffers will almost always be aswell.
 * So, for performance reasons, argument validation can be disabled
 * and removed from the code at compile time to prevent unecessary extra
 * conditionals from being checked at run-time. */
#define ERR_CHK_LVL  0
#if ERR_CHK_LVL == 2
#define VALIDATE(x,y) if (!x || !y) return FAILURE;
#elif ERR_CHK_LVL == 1
#define VALIDATE(x,y) if (!y) return FAILURE;
#else
#define VALIDATE(x,y)
#endif

sfaddr_t* ip6_ret_src(const Packet* p)
{
    VALIDATE(p, 1);

    return &p->ip6h->ip_addrs->ip_src;
}

sfaddr_t* orig_ip6_ret_src(const Packet* p)
{
    VALIDATE(p, 1);

    return &p->orig_ip6h->ip_addrs->ip_src;
}

sfaddr_t* ip6_ret_dst(const Packet* p)
{
    VALIDATE(p, 1);

    return &p->ip6h->ip_addrs->ip_dst;
}

sfaddr_t* orig_ip6_ret_dst(const Packet* p)
{
    VALIDATE(p, 1);

    return &p->orig_ip6h->ip_addrs->ip_dst;
}

uint16_t ip6_ret_toc(const Packet* p)
{
    uint16_t toc;
    VALIDATE(p,1);

    toc = (uint16_t)((ntohl(p->ip6h->vcl) & 0x0FF00000) >> 20);

    return toc;
}

uint16_t orig_ip6_ret_toc(const Packet* p)
{
    uint16_t toc;
    VALIDATE(p,1);

    toc = (uint16_t)((ntohl(p->orig_ip6h->vcl) & 0x0FF00000) >> 20);
    return toc;
}

uint8_t ip6_ret_hops(const Packet* p)
{
//    VALIDATE(p,1);

    return p->ip6h->hop_lmt;
}

uint8_t orig_ip6_ret_hops(const Packet* p)
{
//    VALIDATE(p,1);

    return p->orig_ip6h->hop_lmt;
}

uint16_t ip6_ret_len(const Packet* p)
{
    VALIDATE(p,1);

    /* The length field does not include the header in IPv6, but does in IPv4.
     * To make this analogous to IPv4, for Snort's purposes, we need to tack
     * on the difference. */
    return p->ip6h->len;
}

uint16_t orig_ip6_ret_len(const Packet* p)
{
    VALIDATE(p,1);

    return p->orig_ip6h->len;
}

uint32_t ip6_ret_id(const Packet* p)
{
    IP6Frag* frag_hdr;
    if (p->ip6_extension_count == 0)
        return 0;

    frag_hdr = (IP6Frag*)p->ip6_extensions[p->ip6_frag_index].data;

    return frag_hdr->ip6f_ident;
}

uint32_t orig_ip6_ret_id(const Packet* p)
{
// XXX-IPv6 "NOT YET IMPLEMENTED - IP6 identification"
    return 0;
}

uint8_t ip6_ret_next(const Packet* p)
{
    VALIDATE(p,1);
    return p->ip6h->next;
}

uint8_t orig_ip6_ret_next(const Packet* p)
{
    VALIDATE(p,1);
    return p->orig_ip6h->next;
}

uint16_t ip6_ret_off(const Packet* p)
{
    IP6Frag* frag_hdr;
    if (p->ip6_extension_count == 0)
        return 0;

    frag_hdr = (IP6Frag*)p->ip6_extensions[p->ip6_frag_index].data;

    return frag_hdr->ip6f_offlg;
}

uint16_t orig_ip6_ret_off(const Packet* p)
{
// XXX-IPv6 "NOT YET IMPLEMENTED - IP6 frag offset"
    return 0;
}

uint8_t ip6_ret_ver(const Packet* p)
{
    return (uint8_t)IP6_VER(p->ip6h->vcl);
}

uint8_t orig_ip6_ret_ver(const Packet* p)
{
    return (uint8_t)IP6_VER(p->orig_ip6h->vcl);
}

sfaddr_t* ip4_ret_dst(const Packet* p)
{
    VALIDATE(p,1);
    return &p->ip4h->ip_addrs->ip_dst;
}

sfaddr_t* orig_ip4_ret_dst(const Packet* p)
{
    VALIDATE(p,1);
    return &p->orig_ip4h->ip_addrs->ip_dst;
}

sfaddr_t* ip4_ret_src(const Packet* p)
{
    VALIDATE(p,1);
    return &p->ip4h->ip_addrs->ip_src;
}

sfaddr_t* orig_ip4_ret_src(const Packet* p)
{
    VALIDATE(p,1);
    return &p->orig_ip4h->ip_addrs->ip_src;
}

uint16_t ip4_ret_tos(const Packet* p)
{
    VALIDATE(p,1);

    return p->ip4h->ip_tos;
}

uint16_t orig_ip4_ret_tos(const Packet* p)
{
    VALIDATE(p,1);

    return p->orig_ip4h->ip_tos;
}

uint8_t ip4_ret_ttl(const Packet* p)
{
    VALIDATE(p,1);

    return p->ip4h->ip_ttl;
}

uint8_t orig_ip4_ret_ttl(const Packet* p)
{
    VALIDATE(p,1);

    return p->orig_ip4h->ip_ttl;
}

uint16_t ip4_ret_len(const Packet* p)
{
    VALIDATE(p,1);

    return p->ip4h->ip_len;
}

uint16_t orig_ip4_ret_len(const Packet* p)
{
    VALIDATE(p,1);

    return p->orig_ip4h->ip_len;
}

uint32_t ip4_ret_id(const Packet* p)
{
    VALIDATE(p,1);

    return (uint32_t)p->ip4h->ip_id;
}

uint32_t orig_ip4_ret_id(const Packet* p)
{
    VALIDATE(p,1);

    return (uint32_t)p->orig_ip4h->ip_id;
}

uint8_t ip4_ret_proto(const Packet* p)
{
    // VALIDATION()

    return p->ip4h->ip_proto;
}

uint8_t orig_ip4_ret_proto(const Packet* p)
{
    // VALIDATION()

    return p->orig_ip4h->ip_proto;
}

uint16_t ip4_ret_off(const Packet* p)
{
    return p->ip4h->ip_off;
}

uint16_t orig_ip4_ret_off(const Packet* p)
{
    return p->orig_ip4h->ip_off;
}

uint8_t ip4_ret_ver(const Packet* p)
{
    return IP_VER(p->iph);
}

uint8_t orig_ip4_ret_ver(const Packet* p)
{
    return IP_VER(p->orig_iph);
}

uint8_t ip4_ret_hlen(const Packet* p)
{
    return IP_HLEN(p->iph);
}

uint8_t orig_ip4_ret_hlen(const Packet* p)
{
    return IP_HLEN(p->orig_iph);
}

uint8_t ip6_ret_hlen(const Packet* p)
{
    /* Snort is expecting this number to be in terms of 32 bit words */
    return IP6_HDR_LEN / 4;
}

uint8_t orig_ip6_ret_hlen(const Packet* p)
{
    return IP6_HDR_LEN / 4;
}

IPH_API ip4 =
{
    ip4_ret_src,
    ip4_ret_dst,
    ip4_ret_tos,
    ip4_ret_ttl,
    ip4_ret_len,
    ip4_ret_id,
    ip4_ret_proto,
    ip4_ret_off,
    ip4_ret_ver,
    ip4_ret_hlen,

    orig_ip4_ret_src,
    orig_ip4_ret_dst,
    orig_ip4_ret_tos,
    orig_ip4_ret_ttl,
    orig_ip4_ret_len,
    orig_ip4_ret_id,
    orig_ip4_ret_proto,
    orig_ip4_ret_off,
    orig_ip4_ret_ver,
    orig_ip4_ret_hlen,

    IPH_API_V4
};

IPH_API ip6 =
{
    ip6_ret_src,
    ip6_ret_dst,
    ip6_ret_toc,
    ip6_ret_hops,
    ip6_ret_len,
    ip6_ret_id,
    ip6_ret_next,
    ip6_ret_off,
    ip6_ret_ver,
    ip6_ret_hlen,

    orig_ip6_ret_src,
    orig_ip6_ret_dst,
    orig_ip6_ret_toc,
    orig_ip6_ret_hops,
    orig_ip6_ret_len,
    orig_ip6_ret_id,
    orig_ip6_ret_next,
    orig_ip6_ret_off,
    orig_ip6_ret_ver,
    orig_ip6_ret_hlen,

    IPH_API_V6
};

static inline void _set_callbacks(struct _Packet* p, int family, char orig)
{
    if ( !orig )
    {
        if (family == AF_INET)
            p->iph_api = &ip4;
        else
            p->iph_api = &ip6;

        p->family = family;
    }
    else
    {
        if (family == AF_INET)
            p->orig_iph_api = &ip4;
        else
            p->orig_iph_api = &ip6;

        p->orig_family = family;
    }
}

void set_callbacks(struct _Packet* p, int family, char orig)
{
    _set_callbacks(p, family, orig);
}

void sfiph_build(Packet* p, const void* hdr, int family)
{
    if (!p)
        return;

    _set_callbacks(p, family, CALLBACK_IP);
}

void sfiph_orig_build(Packet* p, const void* hdr, int family)
{
    IP6RawHdr* hdr6;
    IPHdr* hdr4;

    if (!p || !hdr)
        return;

    /* If iph_api is already set, we've been here before.
     * That means this is a nested IP.  */
    if (p->orig_iph_api)
    {
        memcpy(&p->outer_orig_ips, &p->inner_orig_ips, sizeof(p->outer_orig_ips));
        if (p->orig_iph_api->ver == IPH_API_V4)
        {
            memcpy(&p->outer_orig_ip4h, &p->inner_orig_ip4h,
                sizeof(p->outer_orig_ip4h) - sizeof(p->outer_orig_ip4h.ip_addrs));
            p->outer_orig_ip4h.ip_addrs = &p->outer_orig_ips;
            p->outer_orig_iph_api = p->orig_iph_api;
        }
        else if (p->orig_iph_api->ver == IPH_API_V6)
        {
            memcpy(&p->outer_orig_ip6h, &p->inner_orig_ip6h,
                sizeof(p->outer_orig_ip6h) - sizeof(p->outer_orig_ip6h.ip_addrs));
            p->outer_orig_ip6h.ip_addrs = &p->outer_orig_ips;
            p->outer_orig_iph_api = p->orig_iph_api;
        }
    }

    _set_callbacks(p, family, CALLBACK_ICMP_ORIG);

    if (family == AF_INET)
    {
        hdr4 = (IPHdr*)hdr;

        /* The struct Snort uses is identical to the actual IP6 struct,
         * with the exception of the IP addresses. Copy over everything but
         * the IPs */
        memcpy(&p->inner_orig_ip4h, hdr4, sizeof(IPHdr) - 8);
        sfip_set_raw(&p->inner_orig_ips.ip_src, &hdr4->ip_src, family);
        sfip_set_raw(&p->inner_orig_ips.ip_dst, &hdr4->ip_dst, family);
        p->inner_orig_ip4h.ip_addrs = &p->inner_orig_ips;
        p->actual_ip_len = ntohs(p->inner_orig_ip4h.ip_len);
        p->orig_ip4h = &p->inner_orig_ip4h;
    }
    else
    {
        hdr6 = (IP6RawHdr*)hdr;

        /* The struct Snort uses is identical to the actual IP6 struct,
         * with the exception of the IP addresses. Copy over everything but
         * the IPs*/
        memcpy(&p->inner_orig_ip6h, hdr6, sizeof(IP6RawHdr) - 32);
        sfip_set_raw(&p->inner_orig_ips.ip_src, &hdr6->ip6_src, family);
        sfip_set_raw(&p->inner_orig_ips.ip_dst, &hdr6->ip6_dst, family);
        p->inner_orig_ip6h.ip_addrs = &p->inner_orig_ips;
        p->actual_ip_len = ntohs(p->inner_orig_ip6h.len) + IP6_HDR_LEN;
        p->orig_ip6h = &p->inner_orig_ip6h;
    }
}

#ifdef TESTER
int main()
{
    Packet p;
    IP4Hdr i4;
    IP6Hdr i6;

    /* This test assumes we get an IPv4 packet and verifies
     * that the correct callbacks are setup, and they return
     * the correct values. */

    _set_callbacks(&p, AF_INET, CALLBACK_IP);

    /* Same test as above, but with IPv6 */
    _set_callbacks(&p, AF_INET6, CALLBACK_IP);

    return 0;
}

#endif

