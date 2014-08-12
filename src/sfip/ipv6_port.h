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

#ifndef IPV6_PORT_H
#define IPV6_PORT_H

///////////////////
/* IPv6 and IPv4 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfip/sf_ip.h"
#include "sfip/sf_ipvar.h"


#ifdef inet_ntoa
#undef inet_ntoa
#endif
#define inet_ntoa sfip_ntoa

#if 0
typedef const sfip_t *const sfip_t*;
typedef sfip_t *const sfip_t*;
typedef const sfip_t snort_ip;

#define p->ip_api.get_src() ((p)->iph_api->iph_ret_src(p))
#define p->ip_api.get_dst() ((p)->iph_api->iph_ret_dst(p))

/* These are here for backwards compatibility */
#define GET_SRC_ADDR(x) GET_SRC_IP(x)
#define GET_DST_ADDR(x) GET_DST_IP(x)
#define IS_IP4(x) ((x)->family == AF_INET)
#define IS_IP6(x) ((x)->family == AF_INET6)


#define GET_IPH_TOS(p)   (p)->iph_api->iph_ret_tos(p)
#define GET_IPH_LEN(p)   (p)->iph_api->iph_ret_len(p)
#define GET_IPH_TTL(p)   (p)->iph_api->iph_ret_ttl(p)
#define GET_IPH_ID(p)    (p)->iph_api->iph_ret_id(p)
#define GET_IPH_OFF(p)   (p)->iph_api->iph_ret_off(p)
#define GET_IPH_VER(p)   (p)->iph_api->iph_ret_ver(p)

#endif


#if 0
#define p->ip_api.proto() ((uint8_t)(IS_IP6(p) ? ((p)->ip6h->next) : ((p)->iph_api->iph_ret_proto(p))))


#define IS_OUTER_IP4(x) ((x)->outer_family == AF_INET)
#define IS_OUTER_IP6(x) ((x)->outer_family == AF_INET6)

#define GET_ORIG_SRC(p) ((p)->orig_iph_api->orig_iph_ret_src(p))
#define GET_ORIG_DST(p) ((p)->orig_iph_api->orig_iph_ret_dst(p))
#define GET_ORIG_IPH_PROTO(p)   (p)->orig_iph_api->orig_iph_ret_proto(p)
#define GET_ORIG_IPH_VER(p)     (p)->orig_iph_api->orig_iph_ret_ver(p)
#define GET_ORIG_IPH_LEN(p)     (p)->orig_iph_api->orig_iph_ret_len(p)
#define GET_ORIG_IPH_OFF(p)     (p)->orig_iph_api->orig_iph_ret_off(p)
#define GET_ORIG_IPH_PROTO(p)   (p)->orig_iph_api->orig_iph_ret_proto(p)

/* XXX make sure these aren't getting confused with sfip_is_valid within the code */
#define IPH_IS_VALID(p) iph_is_valid(p)

#endif

#define IP_EQUALITY(x,y) (sfip_compare((x),(y)) == SFIP_EQUAL)
#define IP_EQUALITY_UNSET(x,y) (sfip_compare_unset((x),(y)) == SFIP_EQUAL)
#define IP_LESSER(x,y)   (sfip_compare((x),(y)) == SFIP_LESSER)
#define IP_GREATER(x,y)  (sfip_compare((x),(y)) == SFIP_GREATER)



#define IP_CLEAR(x) (x).bits = (x).family = 0; (x).ip32[0] = (x).ip32[1] = (x).ip32[2] = (x).ip32[3] = 0;

#define IP_IS_SET(x) sfip_is_set(&x)

/* This loop trickery is intentional.  If each copy is performed
 * individually on each field, then the following expression gets broken:
 *
 *      if(conditional) IP_COPY_VALUE(a,b);
 *
 * If the macro is instead enclosed in braces, then having a semicolon
 * trailing the macro causes compile breakage.
 * So: use loop. */
#define IP_COPY_VALUE(x,y) \
        do {  \
                (x).bits = (y)->bits; \
                (x).family = (y)->family; \
                (x).ip32[0] = (y)->ip32[0]; \
                (x).ip32[1] = (y)->ip32[1]; \
                (x).ip32[2] = (y)->ip32[2]; \
                (x).ip32[3] = (y)->ip32[3]; \
        } while(0)

#if 0
#define GET_IPH_HLEN(p) ((p)->iph_api->iph_ret_hlen(p))
#define SET_IPH_HLEN(p, val)

#define GET_IP_DGMLEN(p) IS_IP6(p) ? (ntohs(GET_IPH_LEN(p)) + (GET_IPH_HLEN(p) << 2)) : ntohs(GET_IPH_LEN(p))
#define GET_IP_PAYLEN(p) IS_IP6(p) ? ntohs(GET_IPH_LEN(p)) : (ntohs(GET_IPH_LEN(p)) - (GET_IPH_HLEN(p) << 2))


#define GET_INNER_SRC_IP(p)  (IS_IP6(p) ? (&((p)->inner_ip6h.ip_src)):(&((p)->inner_ip4h.ip_src)))
#define GET_INNER_DST_IP(p)  (IS_IP6(p) ? (&((p)->inner_ip6h.ip_dst)):(&((p)->inner_ip4h.ip_dst)))
#endif
#define IP_ARG(ipt)  (&ipt)
#define IP_PTR(ipp)  (ipp)
#define IP_VAL(ipt)  (*ipt)
#define IP_SIZE(ipp) (sfip_size(ipp))

static inline int sfip_equal (const sfip_t *ip1, const sfip_t *ip2)
{
    if ( ip1->family != ip2->family )
    {
        return 0;
    }
    if ( ip1->family == AF_INET )
    {
        return _ip4_cmp(ip1->ip32[0], ip2->ip32[0]) == SFIP_EQUAL;
    }
    if ( ip1->family == AF_INET6 )
    {
        return _ip6_cmp(ip1, ip2) == SFIP_EQUAL;
    }
    return 0;
}

#endif /* IPV6_PORT_H */

