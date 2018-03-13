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
// ipv6.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_IPV6_H
#define PROTOCOLS_IPV6_H

#include <arpa/inet.h>

#include "protocols/protocol_ids.h"

namespace snort
{
namespace ip
{
constexpr uint8_t IP6_HEADER_LEN = 40;
constexpr uint32_t MIN_EXT_LEN = 8;
constexpr uint8_t IP6_MULTICAST = 0xFF;  // first/most significant octet

constexpr uint16_t IP6F_MF_MASK = 0x0001; /* more-fragments flag */
constexpr uint16_t IP6F_RES_MASK = 0x0006; /* reserved bits */

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

struct IP6Hdr
{
    uint32_t ip6_vtf;               /* 4 bits version, 8 bits TC,len
                                        20 bits flow-ID */
    uint16_t ip6_payload_len;               /* payload length */
    IpProtocol ip6_next;                 /* next header */
    uint8_t ip6_hoplim;                /* hop limit */

    snort_in6_addr ip6_src;      /* source address */
    snort_in6_addr ip6_dst;      /* destination address */

    inline uint16_t len() const
    { return ntohs(ip6_payload_len); }

    /* Same function as ipv4 */
    inline IpProtocol proto() const
    { return ip6_next; }

    inline IpProtocol next() const
    { return ip6_next; }

    inline uint8_t hop_lim() const
    { return ip6_hoplim; }

    inline uint8_t ver() const
    { return (uint8_t)(ntohl(ip6_vtf) >> 28); }

    inline uint16_t tos() const
    { return (uint16_t)((ntohl(ip6_vtf) & 0x0FF00000) >> 20); }

    inline uint32_t flow() const
    { return (ntohl(ip6_vtf) & 0x000FFFFF); }

    // because Snort expects this in terms of 32 bit words.
    inline uint8_t hlen() const
    { return IP6_HEADER_LEN; }

    inline const snort_in6_addr* get_src() const
    { return &ip6_src; }

    inline const snort_in6_addr* get_dst() const
    { return &ip6_dst; }

    inline MulticastScope get_dst_multicast_scope() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1] & 0x0F); }

    /* booleans */
    inline bool is_src_multicast() const
    { return (ip6_src.u6_addr8[0] == IP6_MULTICAST); }

    inline bool is_dst_multicast() const
    { return ip6_dst.u6_addr8[0] == IP6_MULTICAST; }

    inline bool is_dst_multicast_scope_reserved() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::RESERVED; }

    inline bool is_dst_multicast_scope_interface() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::INTERFACE; }

    inline bool is_dst_multicast_scope_link() const
    { return static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::LINK; }

    inline bool is_dst_multicast_scope_site() const
    { return (static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::SITE); }

    inline bool is_dst_multicast_scope_global() const
    { return (static_cast<MulticastScope>(ip6_dst.u6_addr8[1]) == MulticastScope::GLOBAL); }

    inline bool is_valid_next_header() const
    {
        switch (ip6_next)
        {
        case IpProtocol::NONEXT:
        case IpProtocol::TCP:
        case IpProtocol::UDP:
        case IpProtocol::ICMPV6:
        case IpProtocol::HOPOPTS:
        case IpProtocol::DSTOPTS:
        case IpProtocol::ROUTING:
        case IpProtocol::FRAGMENT:
        case IpProtocol::MPLS_IP:
        case IpProtocol::GRE:
        case IpProtocol::MOBILITY_IPV6:
            return true;
        default:
            break;
        }
        return false;
    }

    /*  setters  */
    inline void set_len(uint16_t new_len)
    { ip6_payload_len = htons(new_len); }

    inline void set_proto(IpProtocol prot)
    { ip6_next = prot; }

    inline void set_raw_len(uint16_t new_len)
    { ip6_payload_len = new_len; }

    /* Access raw data */

    inline uint16_t raw_len() const
    { return ip6_payload_len; }
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
    const uint8_t* data;
};

/* Generic Extension Header */
struct IP6Extension
{
    IpProtocol ip6e_nxt;
    uint8_t ip6e_len;
    /* options follow */
    uint8_t ip6e_pad[6];
};

/* Fragment header */
struct IP6Frag
{
    IpProtocol ip6f_nxt;       /* next header */
    uint8_t ip6f_reserved;      /* reserved field */
    uint16_t ip6f_offlg;    /* offset, reserved, and flag */
    uint32_t ip6f_ident;    /* identification */

    inline IpProtocol next() const
    { return ip6f_nxt; }

    inline uint16_t off_w_flags() const
    { return ntohs(ip6f_offlg); }

    inline uint16_t off() const
    { return ntohs(ip6f_offlg) & 0xFFF8; }

    inline uint16_t mf() const
    { return ntohs(ip6f_offlg) & IP6F_MF_MASK; }

    inline uint16_t rb() const
    { return ntohs(ip6f_offlg) & IP6F_RES_MASK; }

    inline uint32_t id() const
    { return ntohl(ip6f_ident); }

    inline uint8_t res() const
    { return ip6f_reserved; }

    inline uint16_t raw_off_w_flags() const
    { return ip6f_offlg; }

    inline uint32_t raw_id() const
    { return ip6f_ident; }
};

// Reflects the recommended IPv6 order in RFC 2460 4.1
constexpr int IPV6_ORDER_MAX = 7;
inline int IPV6IdExtensionOrder(const ProtocolId prot_id)
{
    switch (prot_id)
    {
    case ProtocolId::HOPOPTS:   return 1;
    case ProtocolId::DSTOPTS:   return 2;
    case ProtocolId::ROUTING:   return 3;
    case ProtocolId::FRAGMENT:  return 4;
    case ProtocolId::AUTH:      return 5;
    case ProtocolId::ESP:       return 6;
    default:                   return IPV6_ORDER_MAX;
    }
}

inline int IPV6ExtensionOrder(const IpProtocol ip_proto)
{
    return IPV6IdExtensionOrder((ProtocolId)ip_proto);
}
} // namespace ip
} // namespace snort
#endif

