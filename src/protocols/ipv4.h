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

#ifndef PROTOCOLS_IPV4_H
#define PROTOCOLS_IPV4_H

#include <cstdint>


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

#include "sfip/sfip_t.h"
#include "protocols/protocol_ids.h" // include ipv4 protocol numbers




#define ETHERNET_TYPE_IP 0x0800

#ifndef IP_MAXPACKET
#define IP_MAXPACKET    65535        /* maximum packet size */
#endif /* IP_MAXPACKET */


namespace ip
{

namespace detail
{
/* ip option type codes */
constexpr uint32_t IP4_THIS_NET  = 0x00;  // msb
constexpr uint32_t IP4_MULTICAST = 0x0E;  // ms nibble
constexpr uint32_t IP4_RESERVED = 0x0F;  // ms nibble
constexpr uint32_t IP4_LOOPBACK = 0x7F;  // msb
constexpr uint32_t IP4_BROADCAST = 0xffffffff;
} // namespace detail

// not included in details since this should not be hidden
constexpr uint8_t IP4_HEADER_LEN = 20;


enum class IPOptionCodes : std::uint8_t {
    EOL = 0x00,
    NOP = 0x01,
    RR = 0x07,
    TS = 0x44,
    SECURITY = 0x82,
    LSRR = 0x83,
    LSRR_E = 0x84,
    ESEC = 0x85,
    SATID = 0x88,
    SSRR = 0x89,
    RTRALT = 0x94,
    ANY = 0xff,
};


struct IpOptions
{
    uint8_t code;
    uint8_t len; /* length of the data section */
    const uint8_t *data;

    inline bool is_opt_rtralt() const
    { return code == static_cast<uint8_t>(IPOptionCodes::RTRALT); }

    inline bool is_opt_ts() const
    { return code == static_cast<uint8_t>(IPOptionCodes::TS); }

    inline bool is_opt_rr() const
    { return code == static_cast<uint8_t>(IPOptionCodes::RR); }
};


// This must be a standard layour struct!
struct IPHdr
{
    uint8_t ip_verhl;      /* version & header length */
    uint8_t ip_tos;        /* type of service */
    uint16_t ip_len;       /* datagram length */
    uint16_t ip_id;        /* identification  */
    uint16_t ip_off;       /* fragment offset */
    uint8_t ip_ttl;        /* time to live field */
    uint8_t ip_proto;      /* datagram protocol */
    uint16_t ip_csum;      /* checksum */
    uint32_t ip_src;  /* source IP */
    uint32_t ip_dst;  /* dest IP */

    /* getters */
    inline uint8_t get_hlen() const
    { return ip_verhl & 0x0f; }

    inline uint8_t get_ver() const
    { return ((ip_verhl & 0xf0) >> 4); }

    inline uint8_t get_tos() const
    { return ip_tos; };

    inline uint16_t get_len() const
    { return ip_len; }

    inline uint32_t get_id() const
    { return (uint32_t)ip_id; }

    inline uint16_t get_off() const
    { return ip_off; }

    inline uint8_t get_ttl() const
    { return ip_ttl; }

    inline uint8_t get_proto() const
    { return ip_proto; }

    inline uint16_t get_csum() const
    { return ip_csum; }

    inline uint32_t get_src() const
    { return ip_src; }

    inline uint32_t get_dst() const
    { return ip_dst; }

    inline uint8_t get_opt_len() const
    { return (get_hlen() << 2) - IP4_HEADER_LEN; }

    /* booleans */
    inline bool is_src_broadcast() const
    { return ip_src == detail::IP4_BROADCAST; }

    inline bool is_dst_broadcast() const
    { return ip_dst == detail::IP4_BROADCAST; }

    /*  setters  */
    inline void set_hlen(uint8_t value)
    { ip_verhl = (ip_verhl & 0xf0) | (value & 0x0f); }

    inline void set_ip_len(uint16_t value)
    { ip_len = value; }

    inline void set_proto(uint8_t prot)
    { ip_proto = prot; }
} ;


struct IP4Hdr
{
    uint8_t ip_verhl;      /* version & header length */
    uint8_t ip_tos;        /* type of service */
    uint16_t ip_len;       /* datagram length */
    uint16_t ip_id;        /* identification  */
    uint16_t ip_off;       /* fragment offset */
    uint8_t ip_ttl;        /* time to live field */
    uint8_t ip_proto;      /* datagram protocol */
    uint16_t ip_csum;      /* checksum */
    sfip_t ip_src;          /* source IP */
    sfip_t ip_dst;          /* dest IP */
};





static inline bool isPrivateIP(uint32_t addr)
{
    switch (addr & 0xff)
    {
        case 0x0a:
            return true;
            break;
        case 0xac:
            if ((addr & 0xf000) == 0x1000)
                return true;
            break;
        case 0xc0:
            if (((addr & 0xff00) ) == 0xa800)
                return true;
            break;
    }
    return false;
}

static inline bool is_broadcast(uint32_t addr)
{ 
    return (addr == detail::IP4_BROADCAST);
}

static inline bool is_multicast(uint8_t addr)
{
    return (addr == detail::IP4_MULTICAST);
}

static inline bool is_ipv4(uint8_t ch)
{
    return (ch >> 4)  == 4;
}

static inline uint8_t get_pkt_len(const IP4Hdr* p)
{
    return (uint8_t)((p->ip_verhl & 0x0f) << 2);
}

static inline uint8_t get_pkt_len(const IPHdr* p)
{
    return (uint8_t)((p->ip_verhl & 0x0f) << 2);
}

static inline uint8_t get_version(IPHdr* p)
{
    return (p->ip_verhl & 0xf0) >> 4;
}

static inline uint8_t get_version(IP4Hdr* p)
{
    return (p->ip_verhl & 0xf0) >> 4;
}

static inline bool is_loopback(uint8_t addr)
{
    return addr == detail::IP4_LOOPBACK;
}

static inline bool is_this_net(uint8_t addr)
{
    return addr == detail::IP4_THIS_NET;
}

static inline bool is_reserved(uint8_t addr)
{
    return addr == detail::IP4_RESERVED;
}

static inline void set_version(IPHdr* p, uint8_t value)
{
    p->ip_verhl = (unsigned char)((p->ip_verhl & 0x0f) | (value << 4));
}

static inline void set_version(IP4Hdr* p, uint8_t value)
{
    p->ip_verhl = (unsigned char)((p->ip_verhl & 0x0f) | (value << 4));
}

} /* namespace ip */

/* tcpdump shows us the way to cross platform compatibility */

/* we need to change them as well as get them */
// TYPEDEF WHICH NEED TO BE DELETED

typedef ip::IPHdr IPHdr;
typedef ip::IP4Hdr IP4Hdr;


constexpr uint8_t IPOPT_EOL = 0x00;
constexpr uint8_t IPOPT_NOP = 0x01;
constexpr uint8_t IPOPT_RR = 0x07;
constexpr uint8_t IPOPT_TS = 0x44;
constexpr uint8_t IPOPT_SECURITY = 0x82;
constexpr uint8_t IPOPT_LSRR = 0x83;
constexpr uint8_t IPOPT_LSRR_E = 0x84;
constexpr uint8_t IPOPT_ESEC = 0x85;
constexpr uint8_t IPOPT_SATID = 0x88;
constexpr uint8_t IPOPT_SSRR = 0x89;
constexpr uint8_t IPOPT_RTRALT = 0x94;
constexpr uint8_t IPOPT_ANY = 0xff;

/* #define IP_HEADER_LEN ip::ip4_hdr_len() */


#endif

