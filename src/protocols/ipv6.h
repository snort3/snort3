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


#ifndef IPV6_H
#define IPV6_H

#include <cstdint>
#include "sfip/sfip_t.h"

namespace ipv6
{


namespace detail
{
const uint16_t ETHERNET_TYPE_IPV6 = 0x86dd;
const uint8_t IP6_HEADER_LEN = 40;
const uint8_t IP6_MULTICAST = 0xFF;  // first/most significant octet
} // namespace



/* IPv6 address */
#ifndef s6_addr
struct in6_addr
{
    union
    {
        uint8_t u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
    } in6_u;
#define s6_addr         in6_u.u6_addr8
#define s6_addr16       in6_u.u6_addr16
#define s6_addr32       in6_u.u6_addr32
};
#endif


#define ip6flow  ip6_vtf
#define ip6plen  ip6_payload_len
#define ip6nxt   ip6_next
#define ip6hlim  ip6_hoplim
#define ip6hops  ip6_hoplim

#define IPRAW_HDR_VER(p_rawiph) \
   (ntohl(p_rawiph->ip6_vtf) >> 28)

#ifndef IP_PROTO_HOPOPTS
# define IP_PROTO_HOPOPTS    0
#endif

#define IP_PROTO_NONE       59
#define IP_PROTO_ROUTING    43
#define IP_PROTO_FRAGMENT   44
#define IP_PROTO_AH         51
#define IP_PROTO_DSTOPTS    60
#define IP_PROTO_ICMPV6     58
#define IP_PROTO_IPV6       41
#define IP_PROTO_IPIP       4

#define IP6F_OFFSET_MASK    0xfff8  /* mask out offset from _offlg */
#define IP6F_MF_MASK        0x0001  /* more-fragments flag */

#define IP6F_OFFSET(fh) ((ntohs((fh)->ip6f_offlg) & IP6F_OFFSET_MASK) >> 3)
#define IP6F_RES(fh) (fh)->ip6f_reserved
#define IP6F_MF(fh) (ntohs((fh)->ip6f_offlg) & IP6F_MF_MASK )

/* to store references to IP6 Extension Headers */
struct IP6Option
{
    uint8_t type;
    const uint8_t *data;
};

/* Generic Extension Header */
typedef struct _IP6Extension
{
    uint8_t ip6e_nxt;
    uint8_t ip6e_len;
    /* options follow */
    uint8_t ip6e_pad[6];
} IP6Extension;

typedef struct _IP6HopByHop
{
    uint8_t ip6hbh_nxt;
    uint8_t ip6hbh_len;
    /* options follow */
    uint8_t ip6hbh_pad[6];
} IP6HopByHop;

typedef struct _IP6Dest
{
    uint8_t ip6dest_nxt;
    uint8_t ip6dest_len;
    /* options follow */
    uint8_t ip6dest_pad[6];
} IP6Dest;

typedef struct _IP6Route
{
    uint8_t ip6rte_nxt;
    uint8_t ip6rte_len;
    uint8_t ip6rte_type;
    uint8_t ip6rte_seg_left;
    /* type specific data follows */
} IP6Route;

typedef struct _IP6Route0
{
    uint8_t ip6rte0_nxt;
    uint8_t ip6rte0_len;
    uint8_t ip6rte0_type;
    uint8_t ip6rte0_seg_left;
    uint8_t ip6rte0_reserved;
    uint8_t ip6rte0_bitmap[3];
    struct in6_addr ip6rte0_addr[1];  /* Up to 23 IP6 addresses */
} IP6Route0;

/* Fragment header */
typedef struct _IP6Frag
{
    uint8_t   ip6f_nxt;     /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;   /* offset, reserved, and flag */
    uint32_t  ip6f_ident;   /* identification */
} IP6Frag;


struct IP6RawHdr
{
    uint32_t ip6_vtf;               /* 4 bits version, 8 bits TC,
                                        20 bits flow-ID */
    uint16_t ip6_payload_len;               /* payload length */
    uint8_t  ip6_next;                /* next header */
    uint8_t  ip6_hoplim;               /* hop limit */

    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};

struct IP6Hdr
{
    uint32_t vcl;      /* version, class, and label */
    uint16_t len;      /* length of the payload */
    uint8_t  next;     /* next header
                         * Uses the same flags as
                         * the IPv4 protocol field */
    uint8_t  hop_lmt;  /* hop limit */
    sfip_t ip_src;
    sfip_t ip_dst;
};

enum class MulticastScope : uint8_t
{
    IP6_MULTICAST_SCOPE_RESERVED = 0x00,
    IP6_MULTICAST_SCOPE_INTERFACE = 0x01,
    IP6_MULTICAST_SCOPE_LINK = 0x02,
    IP6_MULTICAST_SCOPE_ADMIN = 0x04,
    IP6_MULTICAST_SCOPE_SITE = 0x05,
    IP6_MULTICAST_SCOPE_ORG = 0x08,
    IP6_MULTICAST_SCOPE_GLOBAL = 0x0E,
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



inline uint8_t header_length()
{
    return detail::IP6_HEADER_LEN;
}

inline uint16_t ethertype()
{
    return detail::ETHERNET_TYPE_IPV6;
}

inline bool is_multicast(uint8_t addr)
{
    return addr == detail::IP6_MULTICAST;
}

inline MulticastScope get_multicast_scope(uint8_t ch)
{
    return static_cast<MulticastScope>(ch & 0x0F);
}

inline bool is_multicast_scope_reserved(uint8_t ch)
{
    return (static_cast<MulticastScope>(ch) == MulticastScope::IP6_MULTICAST_SCOPE_RESERVED);
}

inline bool is_multicast_scope_interface(uint8_t ch)
{
    return (static_cast<MulticastScope>(ch) == MulticastScope::IP6_MULTICAST_SCOPE_INTERFACE);
}

inline bool is_multicast_scope_link(uint8_t ch)
{
    return (static_cast<MulticastScope>(ch) == MulticastScope::IP6_MULTICAST_SCOPE_LINK);
}

inline bool is_multicast_scope_site(uint8_t ch)
{
    return (static_cast<MulticastScope>(ch) == MulticastScope::IP6_MULTICAST_SCOPE_SITE);
}

inline bool is_multicast_scope_global(uint8_t ch)
{
    return (static_cast<MulticastScope>(ch) == MulticastScope::IP6_MULTICAST_SCOPE_GLOBAL);
}

inline bool is_ip6_hdr_ver(IP6RawHdr *hdr)
{
    return ((ntohl(hdr->ip6_vtf) >> 28) == 6);
}


} // namespace





// TODO --> delete EVERYTHING below this line!
typedef ipv6::IP6Option IP6Option;
typedef ipv6::IP6Frag IP6Frag;
typedef ipv6::IP6Route IP6Route;
typedef ipv6::IP6HopByHop IP6HopByHop;
typedef ipv6::IP6Dest IP6Dest;
typedef ipv6::IP6Extension IP6Extension;

#endif
