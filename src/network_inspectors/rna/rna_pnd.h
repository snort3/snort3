//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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

#include <limits>

#include "helpers/discovery_filter.h"
#include "host_tracker/host_tracker.h"
#include "protocols/eth.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/vlan.h"
#include "pub_sub/appid_events.h"
#include "sfip/sf_ip.h"

#include "rna_config.h"
#include "rna_logger.h"
#include "rna_mac_cache.h"

#define USHRT_MAX std::numeric_limits<unsigned short>::max()

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

    RnaPnd(const bool en, const std::string& cp, RnaConfig* rc = nullptr) :
        logger(RnaLogger(en)), filter(DiscoveryFilter(cp)), conf(rc)
        { update_timeout = (rc ? rc->update_timeout : 0); }

    void analyze_appid_changes(snort::DataEvent& event);
    void analyze_flow_icmp(const snort::Packet* p);
    void analyze_flow_ip(const snort::Packet* p);
    void analyze_flow_non_ip(const snort::Packet* p);
    void analyze_flow_tcp(const snort::Packet* p, TcpPacketType type);
    void analyze_flow_udp(const snort::Packet* p);

    // generate change event for all hosts in the ip cache
    void generate_change_host_update();

private:
    // generate change event for single host
    void generate_change_host_update(RnaTracker* ht, const snort::Packet* p,
        const snort::SfIp* src_ip, const uint8_t* src_mac, const time_t& sec);
    void generate_change_host_update_eth(HostTrackerMac* mt, const snort::Packet* p,
        const uint8_t* src_mac, const time_t& sec);

    // Change vlan event related utilities
    inline void update_vlan(const snort::Packet* p, HostTrackerMac& hm);
    void generate_change_vlan_update(RnaTracker *rt, const snort::Packet* p,
        const uint8_t* src_mac, HostTrackerMac& hm, bool isnew);
    void generate_change_vlan_update(RnaTracker *rt, const snort::Packet* p,
        const uint8_t* src_mac, const snort::SfIp* src_ip, bool isnew);

    void generate_new_host_mac(const snort::Packet* p, RnaTracker ht, bool discover_proto = false);

    // General rna utilities not associated with flow
    void discover_network_icmp(const snort::Packet* p);
    void discover_network_ip(const snort::Packet* p);
    void discover_network_non_ip(const snort::Packet* p);
    void discover_network_tcp(const snort::Packet* p);
    void discover_network_udp(const snort::Packet* p);
    void discover_network(const snort::Packet* p, uint8_t ttl);

    // RNA utilities for non-IP packets
    void discover_network_ethernet(const snort::Packet* p);
    int discover_network_arp(const snort::Packet* p, RnaTracker* ht_ref);
    int discover_network_bpdu(const snort::Packet* p, const uint8_t* data, RnaTracker ht_ref);
    int discover_switch(const snort::Packet* p, RnaTracker ht_ref);

    RnaLogger logger;
    DiscoveryFilter filter;
    RnaConfig* conf;
    time_t update_timeout;
};

#endif
