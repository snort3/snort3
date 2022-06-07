//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#ifndef RNA_PND_H
#define RNA_PND_H

#include <climits>

#include "helpers/discovery_filter.h"
#include "host_tracker/host_tracker.h"
#include "protocols/eth.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/vlan.h"
#include "pub_sub/appid_events.h"
#include "pub_sub/dhcp_events.h"
#include "pub_sub/netflow_event.h"
#include "pub_sub/smb_events.h"
#include "sfip/sf_ip.h"

#include "rna_config.h"
#include "rna_logger.h"
#include "rna_mac_cache.h"

enum class TcpPacketType
{
    SYN, SYN_ACK, MIDSTREAM
};

#pragma pack(1)
struct RNA_LLC
{
    union
    {
        struct
        {
            uint8_t DSAP;
            uint8_t SSAP;
        } s;
        uint16_t proto;
    } s;
    uint8_t flags;
};
#pragma pack()

static inline bool is_eligible_packet(const snort::Packet* p)
{
    if ( p->has_ip() or
        memcmp(snort::layer::get_eth_layer(p)->ether_src, snort::zero_mac, MAC_SIZE) )
        return true;
    return false;
}

static inline bool is_eligible_ip(const snort::Packet* p)
{
    // If payload needs to be inspected ever, allow rebuilt packet when is_proxied
    if ( !p->has_ip() or p->is_rebuilt() or !p->flow )
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
        // FIXIT-M this code checking the v6 address unconditionally is almost certainly wrong,
        //          especially since it's looking for an IPv4-specific protocol
        if ( !src->is_set() and ((const uint8_t *) dst->get_ip6_ptr())[0] == 0XFF and
            p->ptrs.sp == 68 and p->ptrs.dp == 67 )
            return false; // skip BOOTP
    }
    return true;
}

static inline unsigned short rna_get_eth(const snort::Packet* p)
{
    const snort::vlan::VlanTagHdr* vh = nullptr;
    const snort::eth::EtherHdr* eh = nullptr;

    if (p->proto_bits & PROTO_BIT__VLAN)
        vh = snort::layer::get_vlan_layer(p);

    if (vh)
        return ntohs(vh->vth_proto);
    else if ((eh = snort::layer::get_eth_layer(p)))
        return ntohs(eh->ether_type);
    return USHRT_MAX;
}

class RnaPnd
{
public:

    RnaPnd(const bool en, const std::string& cp, RnaConfig* rc = nullptr);
    ~RnaPnd();

    void analyze_appid_changes(snort::DataEvent&);
    void analyze_flow_icmp(const snort::Packet*);
    void analyze_flow_ip(const snort::Packet*);
    void analyze_flow_non_ip(const snort::Packet*);
    void analyze_flow_tcp(const snort::Packet*, TcpPacketType);
    void analyze_flow_udp(const snort::Packet*);
    void analyze_dhcp_fingerprint(snort::DataEvent&);
    void add_dhcp_info(snort::DataEvent&);
    void analyze_smb_fingerprint(snort::DataEvent&);
    bool analyze_cpe_os_info(snort::DataEvent&);
    bool analyze_netflow(snort::DataEvent&);
    void analyze_netflow_host(snort::NetflowEvent*);
    void analyze_netflow_service(snort::NetflowEvent*);

    // generate change event for all hosts in the ip cache
    void generate_change_host_update();

    static HostCacheIp::Data find_or_create_host_tracker(const snort::SfIp&, bool&);

private:
    // generate change event for single host
    void generate_change_host_update(RnaTracker*, const snort::Packet*,
        const snort::SfIp*, const uint8_t* src_mac, const time_t&);
    void generate_change_host_update_eth(HostTrackerMac*, const snort::Packet*,
        const uint8_t* src_mac, const time_t&);

    void discover_host_types_ttl(RnaTracker&, const snort::Packet*, uint8_t pkt_ttl,
        uint32_t last_seen, const struct in6_addr*, const uint8_t* src_mac);
    int discover_host_types_icmpv6_ndp(RnaTracker& ht, const snort::Packet*, uint32_t last_seen,
        const struct in6_addr* src_ip, const uint8_t* src_mac);

    // Change vlan event related utilities
    inline void update_vlan(const snort::Packet*, HostTrackerMac&);
    void generate_change_vlan_update(RnaTracker*, const snort::Packet*,
        const uint8_t* src_mac, HostTrackerMac&, bool isnew);
    void generate_change_vlan_update(RnaTracker*, const snort::Packet*,
        const uint8_t* src_mac, const snort::SfIp*, bool isnew);

    void generate_new_host_mac(const snort::Packet*, RnaTracker, bool discover_proto = false);

    // General rna utilities not associated with flow
    void discover_network_icmp(const snort::Packet*);
    void discover_network_ip(const snort::Packet*);
    void discover_network_non_ip(const snort::Packet*);
    void discover_network_tcp(const snort::Packet*);
    void discover_network_udp(const snort::Packet*);
    void discover_network(const snort::Packet*, uint8_t ttl);

    // RNA utilities for non-IP packets
    void discover_network_ethernet(const snort::Packet*);
    int discover_network_arp(const snort::Packet*, RnaTracker*);
    int discover_network_bpdu(const snort::Packet*, const uint8_t* data, RnaTracker);
    int discover_network_cdp(const snort::Packet*, const uint8_t* data, uint16_t rlen,
        RnaTracker&);

    int discover_switch(const snort::Packet*, RnaTracker);

    RnaLogger logger;
    DiscoveryFilter filter;
    RnaConfig* conf;
    time_t update_timeout;
};

HostCacheMac* get_host_cache_mac();
void set_host_cache_mac(HostCacheMac* mac_host);

#endif
