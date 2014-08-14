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


#ifndef PROTOCOLS_IPV6_H
#define PROTOCOLS_IPV6_H

#include <cstdint>
#include "sfip/sfip_t.h"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* !WIN32 */
#include <netinet/in_systm.h>
#ifndef IFNAMSIZ
#define IFNAMESIZ MAX_ADAPTER_NAME
#endif /* !IFNAMSIZ */
#endif /* !WIN32 */


namespace ipv6
{


namespace detail
{
constexpr uint8_t IP6_MULTICAST = 0xFF;  // first/most significant octet
constexpr uint32_t MIN_EXT_LEN = 8;
} // namespace

constexpr uint8_t IP6_HEADER_LEN = 40;



#define ip6flow  ip6_vtf
#define ip6plen  ip6_payload_len
#define ip6nxt   ip6_next
#define ip6hlim  ip6_hoplim
#define ip6hops  ip6_hoplim

#define IPRAW_HDR_VER(p_rawiph) \
   (ntohl(p_rawiph->ip6_vtf) >> 28)


#define IP6F_OFFSET_MASK    0xfff8  /* mask out offset from _offlg */
#define IP6F_MF_MASK        0x0001  /* more-fragments flag */

#define IP6F_OFFSET(fh) ((ntohs((fh)->ip6f_offlg) & IP6F_OFFSET_MASK) >> 3)


enum class MulticastScope : uint8_t
{
    RESERVED = 0x00,
    INTERFACE = 0x01,
    LINK = 0x02,
    ADMIN = 0x04,
    SITE = 0x05,
    ORG = 0x08,
    GLOBAL = 0x0E,
};

enum class HopByHopOptions : uint8_t
{
    PAD1 = 0x00,
    PADN = 0x01,
    TUNNEL_ENCAP = 0x04,
    RTALERT = 0x05,
    QUICK_START = 0x06,
    CALIPSO = 0x07,
    HOME_ADDRESS = 0xC9,
    JUMBO = 0xC2,
    ENDPOINT_IDENT = 0x8A,
};

/* to store references to IP6 Extension Headers */
struct IP6Option
{
    uint8_t type;
    const uint8_t *data;
};

/* Generic Extension Header */
struct IP6Extension
{
    uint8_t ip6e_nxt;
    uint8_t ip6e_len;
    /* options follow */
    uint8_t ip6e_pad[6];
} ;


/* Fragment header */
struct IP6Frag
{
    uint8_t   ip6f_nxt;     /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;   /* offset, reserved, and flag */
    uint32_t  ip6f_ident;   /* identification */

    inline uint32_t get_id() const
    { return ip6f_ident; }

    inline uint16_t get_off() const
    { return ip6f_offlg; }
};


/* IPv6 address */
struct snort_in6_addr
{
    union
    {
        uint8_t u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
    };
};


struct IP6RawHdr
{
    uint32_t ip6_vtf;               /* 4 bits version, 8 bits TC,len
                                        20 bits flow-ID */
    uint16_t ip6_payload_len;               /* payload length */
    uint8_t  ip6_next;                /* next header */
    uint8_t  ip6_hoplim;               /* hop limit */

    snort_in6_addr ip6_src;      /* source address */
    snort_in6_addr ip6_dst;      /* destination address */

    inline const snort_in6_addr* get_src() const
    { return &ip6_src; }

    inline const snort_in6_addr* get_dst() const
    { return &ip6_dst; }

    inline uint16_t get_tos() const
    { return (uint16_t)((ntohl(ip6_vtf) & 0x0FF00000) >> 20); }

    inline uint8_t get_hop_lim() const
    { return ip6_hoplim; }

    inline uint16_t get_len() const
    { return ip6_payload_len; }

    inline uint8_t get_next() const
    { return ip6_next; }

    inline uint8_t get_ver() const
    { return (uint8_t)(ntohl(ip6_vtf) >> 28); }

    inline uint8_t get_hdr_len() const
    { return (uint8_t) IP6_HEADER_LEN; }

    // becaise Snort expects this in terms of 32 bit words.
    inline uint8_t get_hlen() const
    { return IP6_HEADER_LEN / 4; }

    inline MulticastScope get_dst_multicast_scope() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1] & 0x0F); }


    /* booleans */
    inline bool is_src_multicast() const
    { return (ip6_src.u6_addr8[0] == detail::IP6_MULTICAST); }

    inline bool is_dst_multicast() const
    { return ip6_dst.u6_addr8[0] == detail::IP6_MULTICAST; }

    inline bool is_multicast_scope_reserved() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::RESERVED; }

    inline bool is_multicast_scope_interface() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::INTERFACE; }

    inline bool is_multicast_scope_link() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::LINK; }

    inline bool is_multicast_scope_site() const
    { return (static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::SITE); }

    inline bool is_multicast_scope_global() const
    { return (static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::GLOBAL); }


    /*  setters  */
    inline void set_len(uint16_t new_len)
    { ip6_payload_len = new_len; }

    inline void set_proto(uint8_t prot)
    { ip6_next = prot; }

};


inline bool is_multicast(uint8_t addr)
{
    return addr == detail::IP6_MULTICAST;
}






inline bool is_ip6_hdr_ver(const IP6RawHdr* const hdr)
{ return ((ntohl(hdr->ip6_vtf) >> 28) == 6); }

inline size_t min_ext_len()
{ return detail::MIN_EXT_LEN; }

inline bool is_mf_set(const IP6Frag* const fh)
{ return (ntohs(fh->ip6f_offlg) & IP6F_MF_MASK); }

inline bool is_res_set(const IP6Frag* const fh)
{ return fh->ip6f_reserved; }

//#define IP6F_RES(fh) (fh)->ip6f_reserved

} // namespace ipv6





// TODO --> delete EVERYTHING below this line!
typedef ipv6::IP6Option IP6Option;
typedef ipv6::IP6Extension IP6Extension;
typedef ipv6::IP6Frag IP6Frag;

#endif
