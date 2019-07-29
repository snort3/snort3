//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// rna_pnd.cc authors: Martin Roesch <roesch@sourcefire.com>
//                     Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_pnd.h"

#include "host_tracker/host_cache.h"

using namespace snort;

static const uint8_t zeromac[6] = {0, 0, 0, 0, 0, 0};

static inline bool is_eligible_packet(const snort::Packet* p)
{
    if ( p->has_ip() or
        memcmp(snort::layer::get_eth_layer(p)->ether_src, zeromac, sizeof(zeromac)) )
        return true;
    return false;
}

static inline bool is_eligible_ip(const snort::Packet* p)
{
    // If payload needs to be inspected ever, allow rebuilt packet when is_proxied
    if ( !is_eligible_packet(p) or p->is_rebuilt() or !p->flow )
        return false;
    return true;
}

static inline bool is_eligible_tcp(const snort::Packet* p)
{
    if ( !is_eligible_ip(p) or p->ptrs.tcph->is_rst() )
        return false;
    return true;
}

static inline bool is_eligible_udp(const snort::Packet* p)
{
    if ( !is_eligible_ip(p) )
        return false;
    if ( p->is_from_client() )
    {
        const snort::SfIp* src = p->ptrs.ip_api.get_src();
        const snort::SfIp* dst = p->ptrs.ip_api.get_dst();
        if ( !src->is_set() and IN6_IS_ADDR_MULTICAST(dst->get_ip6_ptr()) and
            p->ptrs.sp == 68 and p->ptrs.dp == 67 )
            return false; // skip BOOTP
    }
    return true;
}

void RnaPnd::analyze_flow_icmp(const Packet* p)
{
    if ( is_eligible_ip(p) )
        discover_network_icmp(p);
}

void RnaPnd::analyze_flow_ip(const Packet* p)
{
    if ( is_eligible_ip(p) )
        discover_network_ip(p);
}

void RnaPnd::analyze_flow_non_ip(const Packet* p)
{
    if ( is_eligible_packet(p) )
        discover_network_non_ip(p);
}

void RnaPnd::analyze_flow_tcp(const Packet* p, bool is_midstream)
{
    // If and when flow stores rna state, process the flow data here before global cache access
    if ( is_eligible_tcp(p) )
        discover_network_tcp(p);

    UNUSED(is_midstream);
}

void RnaPnd::analyze_flow_udp(const Packet* p)
{
    if ( is_eligible_udp(p) )
        discover_network_udp(p);
}

void RnaPnd::discover_network_icmp(const Packet* p)
{
    if ( !(host_cache[p->flow->client_ip]->
        add_service(p->flow->client_port, p->get_ip_proto_next())) )
        return;
    // process rna discovery for icmp
}

void RnaPnd::discover_network_ip(const Packet* p)
{
    if ( !(host_cache[p->flow->client_ip]->
        add_service(p->flow->client_port, p->get_ip_proto_next())) )
        return;
    // process rna discovery for ip
}

void RnaPnd::discover_network_non_ip(const Packet* p)
{
    // process rna discovery for non-ip in mac cache
    UNUSED(p);
}

void RnaPnd::discover_network_tcp(const Packet* p)
{
    // Track from initiator direction, if not already seen
    if ( !(host_cache[p->flow->client_ip]->
        add_service(p->flow->client_port, p->get_ip_proto_next())) )
        return;

    // Add mac address to ht list, ttl, last_seen, etc.
    // Generate new host events
}

void RnaPnd::discover_network_udp(const Packet* p)
{
    if ( !(host_cache[p->flow->client_ip]->
        add_service(p->flow->client_port, p->get_ip_proto_next())) )
        return;
    // process rna discovery for udp
}

