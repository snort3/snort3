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
// ipv4.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_IPV4_H
#define PROTOCOLS_IPV4_H

#include <arpa/inet.h>

#include "protocols/protocol_ids.h" // include ipv4 protocol numbers

#define ETHERNET_TYPE_IP 0x0800

#ifndef IP_MAXPACKET
#define IP_MAXPACKET    65535        /* maximum packet size */
#endif

namespace snort
{
namespace ip
{
constexpr uint32_t IP4_BROADCAST = 0xffffffff;
constexpr uint8_t IP4_HEADER_LEN = 20;
constexpr uint8_t IP4_THIS_NET  = 0x00;  // msb
constexpr uint8_t IP4_MULTICAST = 0x0E;  // ms nibble
constexpr uint8_t IP4_RESERVED = 0x0F;  // ms nibble
constexpr uint8_t IP4_LOOPBACK = 0x7F;  // msb

// This must be a standard layer struct!
struct IP4Hdr
{
    uint8_t ip_verhl;      /* version & header length */
    uint8_t ip_tos;        /* type of service */
    uint16_t ip_len;       /* datagram length */
    uint16_t ip_id;        /* identification  */
    uint16_t ip_off;       /* fragment offset */
    uint8_t ip_ttl;        /* time to live field */
    IpProtocol ip_proto;      /* datagram protocol */
    uint16_t ip_csum;      /* checksum */
    uint32_t ip_src;  /* source IP */
    uint32_t ip_dst;  /* dest IP */

    /* getters */
    inline uint8_t hlen() const
    { return (uint8_t)((ip_verhl & 0x0f) << 2); }

    inline uint8_t ver() const
    { return (ip_verhl >> 4); }

    inline uint8_t tos() const
    { return ip_tos; }

    inline uint16_t len() const
    { return ntohs(ip_len); }

    inline uint8_t ttl() const
    { return ip_ttl; }

    inline IpProtocol proto() const
    { return ip_proto; }

    inline uint16_t off_w_flags() const
    { return ntohs(ip_off); }

    inline uint16_t rb() const
    { return ntohs(ip_off) & 0x8000; }

    inline uint16_t df() const
    { return ntohs(ip_off) & 0x4000; }

    inline uint16_t mf() const
    { return ntohs(ip_off) & 0x2000; }

    inline uint16_t off() const
    { return (uint16_t)((ntohs(ip_off) & 0x1FFF) << 3); }

    inline uint16_t id() const
    { return ntohs(ip_id); }

    inline uint8_t get_opt_len() const
    { return hlen() - IP4_HEADER_LEN; }

    inline uint16_t csum() const
    { return ntohs(ip_csum); }

    /* booleans */
    inline bool is_src_broadcast() const
    { return ip_src == IP4_BROADCAST; }

    inline bool is_dst_broadcast() const
    { return ip_dst == IP4_BROADCAST; }

    inline bool has_options() const
    { return hlen() > 20; }

    /* Access raw data */
    inline uint16_t raw_len() const
    { return ip_len; }

    inline uint16_t raw_id() const
    { return ip_id; }

    inline uint16_t raw_off() const
    { return ip_off; }

    inline uint16_t raw_csum() const
    { return ip_csum; }

    inline uint32_t get_src() const
    { return ip_src; }

    inline uint32_t get_dst() const
    { return ip_dst; }

    /*  setters  */
    inline void set_hlen(uint8_t value)
    { ip_verhl = (ip_verhl & 0xf0) | (value & 0x0f); }

    inline void set_proto(IpProtocol prot)
    { ip_proto = prot; }

    inline void set_ip_len(uint16_t new_len)
    { ip_len = htons(new_len); }
};

inline bool isPrivateIP(uint32_t addr)
{
    addr = ntohl(addr);
    switch (addr & 0xFF000000)
    {
    case 0x0A000000: // 10.0.0.0/8
        return true;
    case 0xA9000000: // 169.254.0.0/16
        return (addr & 0x00FF0000) == 0x00FE0000;
    case 0xAC000000: // 172.16.0.0/12
        return (addr & 0x00F00000) == 0x00100000;
    case 0xC0000000: // 192.168.0.0/16
        return (addr & 0x00FF0000) == 0x00A80000;
    }
    return false;
}
} // namespace ip
} // namespace snort
/* tcpdump shows us the way to cross platform compatibility */
#endif

