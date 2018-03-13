//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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
// flow_key.cc author Steven Sturges <ssturges@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/flow_key.h"

#include "hash/hashfcn.h"
#include "main/snort_config.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "utils/util.h"

using namespace snort;

//-------------------------------------------------------------------------
// icmp foo
//-------------------------------------------------------------------------

static const uint32_t empty_addr[4] = { 0, 0, 0, 0 };
static const SfIp empty_ip4 = { (void*) &empty_addr, AF_INET };
static const SfIp empty_ip6 = { (void*) &empty_addr, AF_INET6 };

static inline void update_icmp4(const SfIp*& srcIP, uint16_t& srcPort,
    const SfIp*& dstIP, uint16_t& dstPort)
{
    if (srcPort == ICMP_ECHOREPLY)
    {
        /* Treat ICMP echo reply the same as request */
        dstPort = ICMP_ECHO;
        srcPort = 0;
    }
    else if (srcPort == ICMP_ROUTER_ADVERTISE)
    {
        dstPort = ICMP_ROUTER_SOLICIT; /* Treat ICMP router advertisement the same as solicitation */
        srcPort = 0;
        srcIP = &empty_ip4; /* Matching src address to solicit dest address */
    }
    else
    {
        /* otherwise, every ICMP type gets different key */
        dstPort = 0;
        if (srcPort == ICMP_ROUTER_SOLICIT)
            dstIP = &empty_ip4; /* To get unique key, don't use multicast/broadcast addr (RFC 1256) */
    }
}

static inline void update_icmp6(const SfIp*& srcIP, uint16_t& srcPort,
    const SfIp*& dstIP, uint16_t& dstPort)
{
    if (srcPort == icmp::Icmp6Types::ECHO_REPLY)
    {
        /* Treat ICMPv6 echo reply the same as request */
        dstPort = icmp::Icmp6Types::ECHO_REQUEST;
        srcPort = 0;
    }
    else if (srcPort == icmp::Icmp6Types::ROUTER_ADVERTISEMENT)
    {
        dstPort = icmp::Icmp6Types::ROUTER_SOLICITATION; /* Treat ICMPv6 router advertisement the same as solicitation */
        srcPort = 0;
        srcIP = &empty_ip6; /* Matching src address to solicit dest address */
    }
    else
    {
        /* otherwise, every ICMP type gets different key */
        dstPort = 0;
        if (srcPort == icmp::Icmp6Types::ROUTER_SOLICITATION)
            dstIP = &empty_ip6; /* To get unique key, don't use multicast addr (RFC 4861) */
    }
}

//-------------------------------------------------------------------------
// init foo
//-------------------------------------------------------------------------
inline bool FlowKey::init4(
    IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    uint32_t mplsId, bool order)
{
    uint32_t src;
    uint32_t dst;
    bool reversed = false;

    if (ip_proto == IpProtocol::ICMPV4)
        update_icmp4(srcIP, srcPort, dstIP, dstPort);
    
    src = srcIP->get_ip4_value();
    dst = dstIP->get_ip4_value();

    /* These comparisons are done in this fashion for performance reasons */
    if ( !order || src < dst)
    {
        COPY4(ip_l, srcIP->get_ip6_ptr());
        COPY4(ip_h, dstIP->get_ip6_ptr());
        port_l = srcPort;
        port_h = dstPort;
    }
    else if (src == dst)
    {
        COPY4(ip_l, srcIP->get_ip6_ptr());
        COPY4(ip_h, dstIP->get_ip6_ptr());
        if (srcPort < dstPort)
        {
            port_l = srcPort;
            port_h = dstPort;
        }
        else
        {
            port_l = dstPort;
            port_h = srcPort;
            reversed = true;
        }
    }
    else
    {
        COPY4(ip_l, dstIP->get_ip6_ptr());
        port_l = dstPort;
        COPY4(ip_h, srcIP->get_ip6_ptr());
        port_h = srcPort;
        reversed = true;
    }
    if (SnortConfig::mpls_overlapping_ip() &&
        ip::isPrivateIP(src) && ip::isPrivateIP(dst))
        mplsLabel = mplsId;
    else
        mplsLabel = 0;

    return reversed;
}

inline bool FlowKey::init6(
    IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    uint32_t mplsId, bool order)
{
    bool reversed = false;

    if (ip_proto == IpProtocol::ICMPV6)
        update_icmp6(srcIP, srcPort, dstIP, dstPort);
    else if (ip_proto == IpProtocol::ICMPV4)
        update_icmp4(srcIP, srcPort, dstIP, dstPort);

    if ( !order || srcIP->fast_lt6(*dstIP))
    {
        COPY4(ip_l, srcIP->get_ip6_ptr());
        port_l = srcPort;
        COPY4(ip_h, dstIP->get_ip6_ptr());
        port_h = dstPort;
    }
    else if (srcIP->fast_eq6(*dstIP))
    {
        COPY4(ip_l, srcIP->get_ip6_ptr());
        COPY4(ip_h, dstIP->get_ip6_ptr());
        if (srcPort < dstPort)
        {
            port_l = srcPort;
            port_h = dstPort;
        }
        else
        {
            port_l = dstPort;
            port_h = srcPort;
            reversed = true;
        }
    }
    else
    {
        COPY4(ip_l, dstIP->get_ip6_ptr());
        port_l = dstPort;
        COPY4(ip_h, srcIP->get_ip6_ptr());
        port_h = srcPort;
        reversed = true;
    }

    if (SnortConfig::mpls_overlapping_ip())
        mplsLabel = mplsId;
    else
        mplsLabel = 0;

    return reversed;
}

void FlowKey::init_vlan(uint16_t vlanId)
{
    if (!SnortConfig::get_vlan_agnostic())
        vlan_tag = vlanId;
    else
        vlan_tag = 0;
}

void FlowKey::init_address_space(uint16_t addrSpaceId)
{
    if (!SnortConfig::address_space_agnostic())
        addressSpaceId = addrSpaceId;
    else
        addressSpaceId = 0;
}

void FlowKey::init_mpls(uint32_t mplsId)
{
    if (SnortConfig::mpls_overlapping_ip())
        mplsLabel = mplsId;
    else
        mplsLabel = 0;
}

bool FlowKey::init(
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    uint16_t vlanId, uint32_t mplsId, uint16_t addrSpaceId)
{
    bool reversed;

    /* Because the key is going to be used for hash lookups,
     * the key fields will be normalized such that the lower
     * of the IP addresses is stored in ip_l and the port for
     * that IP is stored in port_l.
     */

    if (srcIP->is_ip4())
    {
        version = 4;
        reversed = init4(ip_proto, srcIP, srcPort, dstIP, dstPort, mplsId);
    }
    else
    {
        version = 6;
        reversed = init6(ip_proto, srcIP, srcPort, dstIP, dstPort, mplsId);
    }

    pkt_type = type;
    ip_protocol = (uint8_t)ip_proto;

    init_vlan(vlanId);
    init_address_space(addrSpaceId);
    padding = 0;

    return reversed;
}

bool FlowKey::init(
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, const SfIp *dstIP,
    uint32_t id, uint16_t vlanId,
    uint32_t mplsId, uint16_t addrSpaceId)
{
    // to avoid confusing 2 different datagrams or confusing a datagram
    // with a session, we don't order the addresses and we set version
    uint16_t srcPort = id & 0xFFFF;
    uint16_t dstPort = id >> 16;

    if (srcIP->is_ip4())
    {
        version = 4;
        init4(ip_proto, srcIP, srcPort, dstIP, dstPort, mplsId, false);
        ip_protocol = (uint8_t)ip_proto;
    }
    else
    {
        version = 6;
        init6(ip_proto, srcIP, srcPort, dstIP, dstPort, mplsId, false);
        ip_protocol = 0;
    }

    pkt_type = type;

    init_vlan(vlanId);
    init_address_space(addrSpaceId);
    padding = 0;

    return false;
}

//-------------------------------------------------------------------------
// hash foo
//-------------------------------------------------------------------------

uint32_t FlowKey::hash(HashFnc* hf, const unsigned char* p, int)
{
    uint32_t a, b, c;
    a = b = c = hf->hardener;

    const uint32_t* d = (const uint32_t*)p;

    a += d[0];   // IPv6 lo[0]
    b += d[1];   // IPv6 lo[1]
    c += d[2];   // IPv6 lo[2]

    mix(a, b, c);

    a += d[3];   // IPv6 lo[3]
    b += d[4];   // IPv6 hi[0]
    c += d[5];   // IPv6 hi[1]

    mix(a, b, c);

    a += d[6];   // IPv6 hi[2]
    b += d[7];   // IPv6 hi[3]
    c += d[8];   // mpls label

    mix(a, b, c);

    a += d[9];   // port lo & port hi
    b += d[10];  // vlan tag, address space id
    c += d[11];  // ip_proto, pkt_type, version, and 8bits of zeroed pad, 

    finalize(a, b, c);

    return c;
}

int FlowKey::compare(const void* s1, const void* s2, size_t)
{
    const uint64_t* a,* b;

    a = (const uint64_t*)s1;
    b = (const uint64_t*)s2;
    if (*a - *b)
        return 1;               /* Compares IPv4 lo/hi
                                   Compares IPv6 low[0,1] */

    a++;
    b++;
    if (*a - *b)
        return 1;               /* Compares port lo/hi, vlan, protocol, version
                                   Compares IPv6 low[2,3] */

    a++;
    b++;
    if (*a - *b)
        return 1;               /* Compares IPv6 hi[0,1] */

    a++;
    b++;
    if (*a - *b)
        return 1;               /* Compares IPv6 hi[2,3] */

    a++;
    b++;
    if (*a - *b)
        return 1;               /* Compares MPLS label, port lo/hi */

    a++;
    b++;
    if (*a - *b)
        return 1;               /* Compares vlan,AddressSpace ID,ip_proto,type,version,8 bit pad */

    return 0;
}

