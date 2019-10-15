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

#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#include "rna_logger_common.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static inline bool is_eligible_packet(const Packet* p)
{
    if ( p->has_ip() or
        memcmp(layer::get_eth_layer(p)->ether_src, zero_mac, MAC_SIZE) )
        return true;
    return false;
}

static inline bool is_eligible_ip(const Packet* p)
{
    // If payload needs to be inspected ever, allow rebuilt packet when is_proxied
    if ( !p->has_ip() or p->is_rebuilt() or !p->flow )
        return false;
    return true;
}

static inline bool is_eligible_tcp(const Packet* p)
{
    if ( !is_eligible_ip(p) or p->ptrs.tcph->is_rst() )
        return false;
    return true;
}

static inline bool is_eligible_udp(const Packet* p)
{
    if ( !is_eligible_ip(p) )
        return false;
    if ( p->is_from_client() )
    {
        const SfIp* src = p->ptrs.ip_api.get_src();
        const SfIp* dst = p->ptrs.ip_api.get_dst();
        if ( !src->is_set() and IN6_IS_ADDR_MULTICAST(dst->get_ip6_ptr()) and
            p->ptrs.sp == 68 and p->ptrs.dp == 67 )
            return false; // skip BOOTP
    }
    return true;
}

void RnaPnd::analyze_flow_icmp(const Packet* p)
{
    if ( is_eligible_ip(p) and filter.is_host_monitored(p) )
        discover_network_icmp(p);
}

void RnaPnd::analyze_flow_ip(const Packet* p)
{
    if ( is_eligible_ip(p) and filter.is_host_monitored(p) )
        discover_network_ip(p);
}

void RnaPnd::analyze_flow_non_ip(const Packet* p)
{
    if ( is_eligible_packet(p) and filter.is_host_monitored(p) )
        discover_network_non_ip(p);
}

void RnaPnd::analyze_flow_tcp(const Packet* p, TcpPacketType type)
{
    // If and when flow stores rna state, process the flow data here before global cache access
    if ( is_eligible_tcp(p) and filter.is_host_monitored(p) )
        discover_network_tcp(p);

    UNUSED(type);
}

void RnaPnd::analyze_flow_udp(const Packet* p)
{
    if ( is_eligible_udp(p) and filter.is_host_monitored(p) )
        discover_network_udp(p);
}

void RnaPnd::discover_network_icmp(const Packet* p)
{
    discover_network(p, 0);
}

void RnaPnd::discover_network_ip(const Packet* p)
{
    discover_network(p, p->ptrs.ip_api.ttl());
}

void RnaPnd::discover_network_non_ip(const Packet* p)
{
    // process rna discovery for non-ip in mac cache
    UNUSED(p);
}

void RnaPnd::discover_network_tcp(const Packet* p)
{
    // once fingerprints and other stuff are supported, the discovery code will evolve
    discover_network(p, p->ptrs.ip_api.ttl());
}

void RnaPnd::discover_network_udp(const Packet* p)
{
    const auto& ip_api = p->ptrs.ip_api;
    if ( IN6_IS_ADDR_MULTICAST(ip_api.get_dst()->get_ip6_ptr()) )
        discover_network(p, 0);
    else
        discover_network(p, ip_api.ttl());
}

void RnaPnd::discover_network(const Packet* p, u_int8_t ttl)
{
    bool new_host = false;
    const auto& src_ip = p->ptrs.ip_api.get_src();
    auto ht = host_cache.find_else_create(*src_ip, &new_host);
    if ( !new_host )
        ht->update_last_seen(); // this should be done always and foremost

    const auto& src_mac = layer::get_eth_layer(p)->ether_src;
    ht->add_mac(src_mac, ttl, 0);

    if ( new_host )
    {
        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht,
            (const struct in6_addr*) src_ip->get_ip6_ptr(), src_mac);
    }
    else if ( update_timeout )
        generate_change_host_update(&ht, p, src_ip, src_mac, packet_time());

}

void RnaPnd::generate_change_host_update(RnaTracker* ht, const Packet* p,
    const SfIp* src_ip, const uint8_t* src_mac, time_t sec)
{
    if ( !ht || !update_timeout)
        return;

    uint32_t last_seen = (*ht)->get_last_seen();
    uint32_t last_event = (*ht)->get_last_event();
    time_t timestamp = sec - update_timeout;
    if ( last_seen > last_event && (time_t) last_event + update_timeout <= sec )
        logger.log(RNA_EVENT_CHANGE, CHANGE_HOST_UPDATE, p, ht,
        (const struct in6_addr*) src_ip->get_ip6_ptr(), src_mac, last_seen, (void*) &timestamp);
    // FIXIT-M: deal with host service hits.
}

void RnaPnd::generate_change_host_update()
{
    if ( !update_timeout )
        return;

    auto hosts = host_cache.get_all_data();
    auto sec = time(nullptr);
    for ( auto & h : hosts )
        generate_change_host_update(&h.second, nullptr, &h.first, nullptr, sec);
}

#ifdef UNIT_TEST
TEST_CASE("RNA pnd", "[non-ip]")
{
    SECTION("Testing eligible packet")
    {
        Packet p;
        eth::EtherHdr eh;
        memcpy(eh.ether_src, zero_mac, MAC_SIZE);
        p.num_layers = 1;
        p.layers[0].start = (const uint8_t*) &eh;
        CHECK(is_eligible_packet(&p) == false);

        ip::IP4Hdr h4;
        p.ptrs.ip_api.set(&h4);
        RnaPnd pnd(false, "");
        pnd.analyze_flow_non_ip(&p);
        CHECK(is_eligible_packet(&p) == true);
    }
}
#endif
