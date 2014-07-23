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


#ifndef IPV4_H
#define IPV4_H

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


namespace ipv4
{

namespace detail
{
/* ip option type codes */
const uint32_t IP4_THIS_NET  = 0x00;  // msb
const uint32_t IP4_MULTICAST = 0x0E;  // ms nibble
const uint32_t IP4_RESERVED = 0x0F;  // ms nibble
const uint32_t IP4_LOOPBACK = 0x7F;  // msb
const uint32_t IP4_BROADCAST = 0xffffffff;
const uint8_t IP_HEADER_LEN = 20;
} // namespace detail



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
};

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
    struct in_addr ip_src;  /* source IP */
    struct in_addr ip_dst;  /* dest IP */
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


static inline uint16_t prot_id()
{
    return IPPROTO_ID_IPIP;
}

static inline int ethertype_ip()
{
    return ETHERTYPE_IPV4;
}

static inline bool is_broadcast(uint32_t addr)
{ 
    return (addr == detail::IP4_BROADCAST);
}

static inline bool is_multicast(uint8_t addr)
{
    return (addr == detail::IP4_MULTICAST);
}

static inline bool is_opt_rr(IPOptionCodes code)
{
    return (code == IPOptionCodes::RR);
}

static inline bool is_opt_rr(uint8_t code)
{
    return (static_cast<IPOptionCodes>(code) == IPOptionCodes::RR);
}

static inline bool is_opt_rtralt(IPOptionCodes code)
{
    return (code == IPOptionCodes::RTRALT);
}

static inline bool is_opt_rtralt(uint8_t code)
{
    return (static_cast<IPOptionCodes>(code) == IPOptionCodes::RTRALT);
}

static inline bool is_opt_ts(IPOptionCodes code)
{
    return (code == IPOptionCodes::TS);
}

static inline bool is_opt_ts(uint8_t code)
{
    return (static_cast<IPOptionCodes>(code) == IPOptionCodes::TS);
}

static inline bool is_ethertype_ip(int proto)
{
    return (proto == ETHERTYPE_IPV4);
}

static inline bool is_ipv4(IPHdr* p)
{
    return (p->ip_verhl >> 4) == 4;
}

static inline bool is_ipv4(const IP4Hdr* p)
{
    return (p->ip_verhl >> 4)  == 4;
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

static inline uint8_t hdr_len()
{
    return detail::IP_HEADER_LEN;
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

static inline void set_hlen(IPHdr* p, uint8_t value)
{
    p->ip_verhl = (unsigned char)(((p)->ip_verhl & 0xf0) | (value & 0x0f));
}

static inline void set_hlen(IP4Hdr* p, uint8_t value)
{
    p->ip_verhl = (unsigned char)(((p)->ip_verhl & 0xf0) | (value & 0x0f));
}

} /* namespace ipv4 */

/* tcpdump shows us the way to cross platform compatibility */

/* we need to change them as well as get them */
// TYPEDEF WHICH NEED TO BE DELETED

typedef ipv4::IPHdr IPHdr;
typedef ipv4::IP4Hdr IP4Hdr;


const uint8_t IPOPT_EOL = 0x00;
const uint8_t IPOPT_NOP = 0x01;
const uint8_t IPOPT_RR = 0x07;
const uint8_t IPOPT_TS = 0x44;
const uint8_t IPOPT_SECURITY = 0x82;
const uint8_t IPOPT_LSRR = 0x83;
const uint8_t IPOPT_LSRR_E = 0x84;
const uint8_t IPOPT_ESEC = 0x85;
const uint8_t IPOPT_SATID = 0x88;
const uint8_t IPOPT_SSRR = 0x89;
const uint8_t IPOPT_RTRALT = 0x94;
const uint8_t IPOPT_ANY = 0xff;

#define IP_HEADER_LEN ipv4::hdr_len()


#endif

