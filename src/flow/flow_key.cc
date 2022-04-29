//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "hash/hash_key_operations.h"
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
inline bool FlowKey::init4(IpProtocol ip_proto, const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort, bool order)
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

    return reversed;
}

inline bool FlowKey::init6(IpProtocol ip_proto, const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort, bool order)
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

    return reversed;
}

void FlowKey::init_vlan(const SnortConfig* sc, uint16_t vlanId)
{
    if (!sc->get_vlan_agnostic())
        vlan_tag = vlanId;
    else
        vlan_tag = 0;
}

void FlowKey::init_address_space(const SnortConfig* sc, uint32_t addrSpaceId)
{
    if (!sc->address_space_agnostic())
        addressSpaceId = addrSpaceId;
    else
        addressSpaceId = 0;
}

void FlowKey::init_groups(int16_t ingress_group, int16_t egress_group, bool rev)
{
    if (flags.group_used)
    {
        if (rev)
        {
            group_l = egress_group;
            group_h = ingress_group;
        }
        else
        {
            group_l = ingress_group;
            group_h = egress_group;
        }
    }
    else
        group_l = group_h = DAQ_PKTHDR_UNKNOWN;
}

void FlowKey::init_mpls(const SnortConfig* sc, uint32_t mplsId)
{
    if (!sc->get_mpls_agnostic())
        mplsLabel = mplsId;
    else
        mplsLabel = 0;
}

bool FlowKey::init(
    const SnortConfig* sc,
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    uint16_t vlanId, uint32_t mplsId,
    uint32_t addrSpaceId, int16_t ingress_group,
    int16_t egress_group)
{
    bool reversed;

    /* Because the key is going to be used for hash lookups,
     * the key fields will be normalized such that the lower
     * of the IP addresses is stored in ip_l and the port for
     * that IP is stored in port_l.
     */

    if (srcIP->is_ip4() && dstIP->is_ip4())
    {
        version = 4;
        reversed = init4(ip_proto, srcIP, srcPort, dstIP, dstPort);
    }
    else
    {
        version = 6;
        reversed = init6(ip_proto, srcIP, srcPort, dstIP, dstPort);
    }

    pkt_type = type;
    ip_protocol = (uint8_t)ip_proto;

    init_vlan(sc, vlanId);
    init_address_space(sc, addrSpaceId);
    init_mpls(sc, mplsId);

    padding = flags.padding_bits = 0;

    flags.group_used = (ingress_group != DAQ_PKTHDR_UNKNOWN and egress_group != DAQ_PKTHDR_UNKNOWN);
    init_groups(ingress_group, egress_group, reversed);

    return reversed;
}

bool FlowKey::init(
    const SnortConfig* sc,
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    uint16_t vlanId, uint32_t mplsId,
    const DAQ_PktHdr_t& pkt_hdr)
{
    bool reversed;

    /* Because the key is going to be used for hash lookups,
     * the key fields will be normalized such that the lower
     * of the IP addresses is stored in ip_l and the port for
     * that IP is stored in port_l.
     */

    if (srcIP->is_ip4() && dstIP->is_ip4())
    {
        version = 4;
        reversed = init4(ip_proto, srcIP, srcPort, dstIP, dstPort);
    }
    else
    {
        version = 6;
        reversed = init6(ip_proto, srcIP, srcPort, dstIP, dstPort);
    }

    pkt_type = type;
    ip_protocol = (uint8_t)ip_proto;

    init_vlan(sc, vlanId);
    init_address_space(sc, pkt_hdr.address_space_id);
    init_mpls(sc, mplsId);

    padding = flags.padding_bits = 0;
    flags.group_used = ((pkt_hdr.flags & DAQ_PKT_FLAG_SIGNIFICANT_GROUPS) != 0);
    init_groups(pkt_hdr.ingress_group, pkt_hdr.egress_group, reversed);

    return reversed;
}

bool FlowKey::init(
    const SnortConfig* sc,
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, const SfIp *dstIP,
    uint32_t id, uint16_t vlanId,
    uint32_t mplsId, uint32_t addrSpaceId,
    int16_t ingress_group, int16_t egress_group)
{
    // to avoid confusing 2 different datagrams or confusing a datagram
    // with a session, we don't order the addresses and we set version

    uint16_t srcPort = id & 0xFFFF;
    uint16_t dstPort = id >> 16;
    bool reversed;

    if (srcIP->is_ip4() && dstIP->is_ip4())
    {
        version = 4;
        reversed = init4(ip_proto, srcIP, srcPort, dstIP, dstPort, false);
        ip_protocol = (uint8_t)ip_proto;
    }
    else
    {
        version = 6;
        reversed = init6(ip_proto, srcIP, srcPort, dstIP, dstPort, false);
        ip_protocol = 0;
    }

    pkt_type = type;

    init_vlan(sc, vlanId);
    init_address_space(sc, addrSpaceId);
    init_mpls(sc, mplsId);

    padding = flags.padding_bits = 0;

    flags.group_used = (ingress_group != DAQ_PKTHDR_UNKNOWN and egress_group != DAQ_PKTHDR_UNKNOWN);
    init_groups(ingress_group, egress_group, reversed);

    return false;
}

bool FlowKey::init(
    const SnortConfig* sc,
    PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, const SfIp *dstIP,
    uint32_t id, uint16_t vlanId,
    uint32_t mplsId, const DAQ_PktHdr_t& pkt_hdr)
{
    // to avoid confusing 2 different datagrams or confusing a datagram
    // with a session, we don't order the addresses and we set version

    uint16_t srcPort = id & 0xFFFF;
    uint16_t dstPort = id >> 16;
    bool reversed;

    if (srcIP->is_ip4() && dstIP->is_ip4())
    {
        version = 4;
        reversed = init4(ip_proto, srcIP, srcPort, dstIP, dstPort, false);
        ip_protocol = (uint8_t)ip_proto;
    }
    else
    {
        version = 6;
        reversed = init6(ip_proto, srcIP, srcPort, dstIP, dstPort, false);
        ip_protocol = 0;
    }

    pkt_type = type;

    init_vlan(sc, vlanId);
    init_address_space(sc, pkt_hdr.address_space_id);
    init_mpls(sc, mplsId);

    padding = flags.padding_bits = 0;

    flags.group_used = ((pkt_hdr.flags & DAQ_PKT_FLAG_SIGNIFICANT_GROUPS) != 0);
    init_groups(pkt_hdr.ingress_group, pkt_hdr.egress_group, reversed);

    return false;
}

//-------------------------------------------------------------------------
//-------------------------------------------------------------------------
// hash foo
//-------------------------------------------------------------------------

bool FlowKey::is_equal(const void* s1, const void* s2, size_t)
{
    const uint64_t* a = (const uint64_t*)s1;
    const uint64_t* b = (const uint64_t*)s2;

    if (*a - *b)
        return false;               /* Compares IPv4 lo/hi
                                   Compares IPv6 low[0,1] */

    a++;
    b++;
    if (*a - *b)
        return false;               /* Compares port lo/hi, vlan, protocol, version
                                   Compares IPv6 low[2,3] */

    a++;
    b++;
    if (*a - *b)
        return false;               /* Compares IPv6 hi[0,1] */

    a++;
    b++;
    if (*a - *b)
        return false;               /* Compares IPv6 hi[2,3] */

    a++;
    b++;
    if (*a - *b)
        return false;               /* Compares MPLS label, addressSpaceId */

    a++;
    b++;
    if (*a - *b)
        return false;               /* Compares port lo/hi, group lo/hi, vlan */

    a++;
    b++;
    if (*a - *b)
        return false;               /* vlan, pad, ip_proto, type, version, flags */

    return true;
}

unsigned FlowHashKeyOps::do_hash(const unsigned char* k, int)
{
    uint32_t a, b, c;
    a = b = c = hardener;

    const uint32_t* d = (const uint32_t*)k;

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

    a += d[9];   // addressSpaceId
    b += d[10];  // port lo & port hi
    c += d[11];  // group lo & group hi

    mix(a, b, c);

    a += d[12];  // vlan & pad
    b += d[13];  // ip_proto, pkt_type, version, flags

    finalize(a, b, c);

    return c;
}

bool FlowHashKeyOps::key_compare(const void* k1, const void* k2, size_t len)
{
    return FlowKey::is_equal(k1, k2, len);
}


