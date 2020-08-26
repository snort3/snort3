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

// rna_pnd.cc authors: Martin Roesch <roesch@sourcefire.com>
//                     Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_pnd.h"

#include <algorithm>

#include "protocols/arp.h"
#include "protocols/bpdu.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"
#include "protocols/protocol_ids.h"
#include "protocols/tcp.h"

#include "rna_fingerprint_tcp.h"
#include "rna_logger_common.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace snort::bpdu;
using namespace std;

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
        // FIXIT-M this code checking the v6 address unconditionally is almost certainly wrong,
        //          especially since it's looking for an IPv4-specific protocol
        if ( !src->is_set() and ((const uint8_t *) dst->get_ip6_ptr())[0] == 0XFF and
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
    if ( is_eligible_tcp(p) )
    {
        // If it's a tcp SYN packet, create a fingerprint state for
        // the SYN-ACK, but only if we're monitoring the destination (server)
        const auto& dst_ip = p->ptrs.ip_api.get_dst();
        if ( type == TcpPacketType::SYN && filter.is_host_monitored(p, nullptr, dst_ip) )
        {
            RNAFlow* rna_flow = new RNAFlow();
            p->flow->set_flow_data(rna_flow);
            rna_flow->state.set(p);
        }

        if ( filter.is_host_monitored(p) )
            discover_network_tcp(p);
    }
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
    discover_network_ethernet(p);
}

void RnaPnd::discover_network_tcp(const Packet* p)
{
    // once fingerprints and other stuff are supported, the discovery code will evolve
    discover_network(p, p->ptrs.ip_api.ttl());
}

void RnaPnd::discover_network_udp(const Packet* p)
{
    const auto& ip_api = p->ptrs.ip_api;
    // FIXIT-L this used to be IN6_IS_ADDR_MULTICAST(), SfIp should implement something comparable
    if ( ((const uint8_t *) ip_api.get_dst()->get_ip6_ptr())[0] == 0XFF )
        discover_network(p, 0);
    else
        discover_network(p, ip_api.ttl());
}

void RnaPnd::discover_network(const Packet* p, uint8_t ttl)
{
    bool new_host = false;
    bool new_mac = false;
    const auto& src_ip = p->ptrs.ip_api.get_src();
    const auto& src_ip_ptr = (const struct in6_addr*) src_ip->get_ip6_ptr();

    auto ht = host_cache.find_else_create(*src_ip, &new_host);

    if ( !new_host )
        ht->update_last_seen(); // this should be done always and foremost

    const auto& src_mac = layer::get_eth_layer(p)->ether_src;

    new_mac = ht->add_mac(src_mac, ttl, 0);

    if ( new_host )
        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht, src_ip_ptr, src_mac);

    if ( new_mac and !new_host )
        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_ADD, p, &ht,
            src_ip_ptr, src_mac, packet_time(), nullptr, ht->get_hostmac(src_mac));

    if ( ht->update_mac_ttl(src_mac, ttl) )
    {
        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_INFO, p, &ht,
            src_ip_ptr, src_mac, packet_time(), nullptr, ht->get_hostmac(src_mac));

        HostMac* hm = ht->get_max_ttl_hostmac();
        if (hm and hm->primary and ht->get_hops())
        {
            ht->update_hops(0);
            logger.log(RNA_EVENT_CHANGE, CHANGE_HOPS, p, &ht, src_ip_ptr, src_mac, packet_time());
        }
    }

    uint16_t ptype = rna_get_eth(p);
    if ( ptype > to_utype(ProtocolId::ETHERTYPE_MINIMUM) )
    {
        if ( ht->add_network_proto(ptype) )
            logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, src_ip_ptr, src_mac,
                packet_time(), nullptr, nullptr, ptype);
    }

    ptype = to_utype(p->get_ip_proto_next());
    if ( ht->add_xport_proto(ptype) )
        logger.log(RNA_EVENT_NEW, NEW_XPORT_PROTOCOL, p, &ht, src_ip_ptr, src_mac,
            packet_time(), nullptr, nullptr, ptype);

    if ( !new_host )
    {
        generate_change_host_update(&ht, p, src_ip, src_mac, packet_time());
    }

    // Fingerprint stuff
    const TcpFpProcessor* processor;
    if ( p->is_tcp() && (processor = get_tcp_fp_processor()) != nullptr )
    {
        RNAFlow* rna_flow = nullptr;
        if ( p->ptrs.tcph->is_syn_ack() )
            rna_flow = (RNAFlow*) p->flow->get_flow_data(RNAFlow::inspector_id);
        const TcpFingerprint* tfp = processor->get(p, rna_flow);

        if (tfp && ht->add_tcp_fingerprint(tfp->fpid))
        {
            logger.log(RNA_EVENT_NEW, NEW_OS, p, &ht, src_ip_ptr,
                src_mac, 0, nullptr, nullptr, ptype, tfp);
        }
    }
}

inline void RnaPnd::update_vlan(const Packet* p, HostTrackerMac& hm)
{
    if (!(p->proto_bits & PROTO_BIT__VLAN))
        return;

    const vlan::VlanTagHdr* vh = layer::get_vlan_layer(p);

    if (vh)
        hm.update_vlan(vh->vth_pri_cfi_vlan, vh->vth_proto);
}

void RnaPnd::generate_change_vlan_update(RnaTracker *rt, const Packet* p,
    const uint8_t* src_mac, HostTrackerMac& hm, bool isnew)
{
    if (!(p->proto_bits & PROTO_BIT__VLAN))
        return;

    const vlan::VlanTagHdr* vh = layer::get_vlan_layer(p);

    if (!vh)
        return;

    if (isnew or !hm.has_vlan() or hm.get_vlan() != vh->vth_pri_cfi_vlan)
    {
        if (!isnew)
            update_vlan(p, hm);

        rt->get()->update_vlan(vh->vth_pri_cfi_vlan, vh->vth_proto);
        logger.log(RNA_EVENT_CHANGE, CHANGE_VLAN_TAG, p, rt, nullptr,
            src_mac, rt->get()->get_last_seen());
    }
}

void RnaPnd::generate_change_vlan_update(RnaTracker *rt, const Packet* p,
    const uint8_t* src_mac, const SfIp* src_ip, bool isnew)
{
    if (!(p->proto_bits & PROTO_BIT__VLAN))
        return;

    const vlan::VlanTagHdr* vh = layer::get_vlan_layer(p);

    if (!vh)
        return;

    if (isnew or !rt->get()->has_vlan() or rt->get()->get_vlan() != vh->vth_pri_cfi_vlan)
    {
        rt->get()->update_vlan(vh->vth_pri_cfi_vlan, vh->vth_proto);
        logger.log(RNA_EVENT_CHANGE, CHANGE_VLAN_TAG, p, rt,
            (const struct in6_addr*) src_ip->get_ip6_ptr(),
            src_mac, rt->get()->get_last_seen());
    }
}

void RnaPnd::generate_change_host_update(RnaTracker* ht, const Packet* p,
    const SfIp* src_ip, const uint8_t* src_mac, const time_t& sec)
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


void RnaPnd::generate_change_host_update_eth(HostTrackerMac* mt, const Packet* p,
    const uint8_t* src_mac, const time_t& sec)
{
    if ( !mt || !update_timeout)
        return;

    // Create and populate a new HostTracker solely for event logging
    RnaTracker rt = shared_ptr<snort::HostTracker>(new HostTracker());
    rt->update_last_seen();
    rt->add_mac(src_mac, 0, 1);

    auto protos = mt->get_network_protos();
    auto total = protos.size();
    while( total-- )
        rt->add_network_proto(protos[total]);

    uint32_t last_seen = mt->get_last_seen();
    uint32_t last_event = mt->get_last_event();
    time_t timestamp = sec - update_timeout;

    if ( last_seen > last_event && (time_t) last_event + update_timeout <= sec )
    {
        logger.log(RNA_EVENT_CHANGE, CHANGE_HOST_UPDATE, p, &rt,
            nullptr, src_mac, last_seen, (void*) &timestamp);

        mt->update_last_event(sec);
    }

}

void RnaPnd::generate_change_host_update()
{
    if ( !update_timeout )
        return;

    auto hosts = host_cache.get_all_data();
    auto mac_hosts = host_cache_mac.get_all_data();
    auto sec = time(nullptr);

    for ( auto & h : hosts )
        generate_change_host_update(&h.second, nullptr, &h.first, nullptr, sec);

    for ( auto & m : mac_hosts)
        generate_change_host_update_eth(m.second.get(), nullptr,
            (const uint8_t*) &m.first.mac_addr, sec);
}

void RnaPnd::generate_new_host_mac(const Packet* p, RnaTracker ht, bool discover_proto)
{
    // In general, this is the default case for mac eventing.
    // Ex. if BPDU dsap, ssap checks fail, we fallback here to
    // generate a new_host event

    bool new_host_mac = false;
    MacKey mk(layer::get_eth_layer(p)->ether_src);

    auto hm_ptr = host_cache_mac.find_else_create(mk, &new_host_mac);

    if (new_host_mac)
    {
        update_vlan(p, *hm_ptr);

        ht.get()->update_last_seen();
        ht.get()->add_mac(mk.mac_addr, 0, 0);

        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht, nullptr, mk.mac_addr);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
        generate_change_vlan_update(&ht, p, mk.mac_addr, *hm_ptr, true);
    }
    else
    {
        generate_change_host_update_eth(hm_ptr.get(), p, mk.mac_addr, packet_time());
        hm_ptr->update_last_seen(p->pkth->ts.tv_sec);
        generate_change_vlan_update(&ht, p, mk.mac_addr, *hm_ptr, false);
    }

    if (discover_proto)
    {
        uint16_t ntype = rna_get_eth(p);
        if ( ntype > to_utype(ProtocolId::ETHERTYPE_MINIMUM) )
        {
            if ( hm_ptr->add_network_proto(ntype) )
            {
                logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, nullptr, mk.mac_addr,
                    0, nullptr, nullptr, ntype);
                hm_ptr->update_last_event(p->pkth->ts.tv_sec);
            }
        }
        else if ( ntype != to_utype(ProtocolId::ETHERTYPE_NOT_SET) )
        {
            const Layer& lyr = p->layers[p->num_layers-1];
            if ( lyr.prot_id == ProtocolId::ETHERNET_LLC )
            {
                ntype = ((const RNA_LLC*) lyr.start)->s.proto;
                if ( hm_ptr->add_network_proto(ntype) )
                {
                    logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, nullptr, mk.mac_addr,
                        0, nullptr, nullptr, ntype);
                    hm_ptr->update_last_event(p->pkth->ts.tv_sec);
                }
            }
        }
    }
}

// RNA Flow Tracking for non-IP connections (ARP, BPDU, CDP)
void RnaPnd::discover_network_ethernet(const Packet* p)
{
    #define BPDU_ID 0x42
    #define SNAP_ID 0xAA
    int retval = 1;
    RnaTracker rt = shared_ptr<snort::HostTracker>(new HostTracker());

    if (!p->is_eth())
        return;

    if (layer::get_arp_layer(p))
        retval = discover_network_arp(p, &rt);
    else
    {
        // If we have an inner LLC layer, grab it
        const Layer& lyr = p->layers[p->num_layers-1];
        if (lyr.prot_id == ProtocolId::ETHERNET_LLC)
        {
            uint16_t etherType = rna_get_eth(p);

            if (!etherType || etherType > static_cast<uint16_t>(ProtocolId::ETHERTYPE_MINIMUM))
            {
                generate_new_host_mac(p, rt);
                return;
            }

            const RNA_LLC* llc = (const RNA_LLC*) lyr.start;

            if (llc->s.s.DSAP != llc->s.s.SSAP)
            {
                generate_new_host_mac(p, rt);
                return;
            }

            switch (llc->s.s.DSAP)
            {
                case BPDU_ID:
                {
                    retval = discover_network_bpdu(p, ((const uint8_t*)llc + sizeof(RNA_LLC)), rt);
                    break;
                }

                default:
                    break;
            }
        }
    }

    if (retval)
        generate_new_host_mac(p, rt, true);

    return;
}

int RnaPnd::discover_network_arp(const Packet* p, RnaTracker* ht_ref)
{
    MacKey mk(layer::get_eth_layer(p)->ether_src);
    const auto& src_mac = mk.mac_addr;

    const snort::arp::EtherARP *ah = layer::get_arp_layer(p);

    if (ntohs(ah->ea_hdr.ar_hrd) != 0x0001)
        return 1;
    if (ntohs(ah->ea_hdr.ar_pro) != 0x0800)
        return 1;
    if (ah->ea_hdr.ar_hln != 6 || ah->ea_hdr.ar_pln != 4)
        return 1;
    if ((ntohs(ah->ea_hdr.ar_op) != 0x0002))
        return 1;
    if (memcmp(src_mac, ah->arp_sha, MAC_SIZE))
        return 1;
    if (!ah->arp_spa32)
        return 1;

    SfIp spa(ah->arp_spa, AF_INET);

    // In the case where SPA is not monitored, log as a generic "NEW MAC"
    if ( !(filter.is_host_monitored(p, nullptr, &spa) ))
        return 1;

    bool new_host = false;
    bool new_host_mac = false;
    auto ht = host_cache.find_else_create(spa, &new_host);
    auto hm_ptr = host_cache_mac.find_else_create(mk, &new_host_mac);

    if (!new_host_mac)
        hm_ptr->update_last_seen(p->pkth->ts.tv_sec);

    *ht_ref = ht;

    if( new_host )
    {
        ht->update_hops(255);
        ht->add_mac(src_mac, 0, 0);
        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht,
            (const struct in6_addr*) spa.get_ip6_ptr(), src_mac);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }

    if ( ht->add_mac(src_mac, 0, 0) )
    {
        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_ADD, p, ht_ref,
            (const struct in6_addr*) spa.get_ip6_ptr(), src_mac,
            0, nullptr, ht->get_hostmac(src_mac));
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }
    else if (ht->make_primary(src_mac))
    {
        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_INFO, p, ht_ref,
            (const struct in6_addr*) spa.get_ip6_ptr(), src_mac,
            0, nullptr, ht->get_hostmac(src_mac));
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }

    generate_change_vlan_update(&ht, p, src_mac, &spa, true);
    auto ntype = to_utype(ProtocolId::ETHERTYPE_ARP);

    if ( hm_ptr->add_network_proto(ntype) )
    {
        logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, nullptr, src_mac,
            0, nullptr, nullptr, ntype);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }

    if ( ht->get_hops() )
    {
        ht->update_hops(0);
        logger.log(RNA_EVENT_CHANGE, CHANGE_HOPS, p, ht_ref,
            (const struct in6_addr*) spa.get_ip6_ptr(), src_mac, 0, nullptr,
             ht->get_hostmac(src_mac));
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }

    if ( !new_host )
        generate_change_host_update_eth(hm_ptr.get(), p, src_mac, packet_time());

    return 0;
}

int RnaPnd::discover_network_bpdu(const Packet* p, const uint8_t* data,
    RnaTracker ht_ref)
{
    const uint8_t* dst_mac = layer::get_eth_layer(p)->ether_dst;

    const BPDUData* stp;

    if (!isBPDU(dst_mac))
        return 1;
    stp = reinterpret_cast<const BPDUData*>(data);
    if (stp->id || stp->version)
        return 1;
    if (stp->type !=  BPDU_TYPE_TOPCHANGE)
        return 1;

    return discover_switch(p, ht_ref);
}

int RnaPnd::discover_switch(const Packet* p, RnaTracker ht_ref)
{
    bool new_host_mac = false;
    MacKey mk(layer::get_eth_layer(p)->ether_src);

    auto hm_ptr = host_cache_mac.find_else_create(mk, &new_host_mac);

    if (new_host_mac)
    {
        hm_ptr->host_type = HOST_TYPE_BRIDGE;
        update_vlan(p, *hm_ptr);

        hm_ptr->update_last_event(p->pkth->ts.tv_sec);

        ht_ref.get()->update_last_seen();
        ht_ref.get()->add_mac(mk.mac_addr, 0, 1);

        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht_ref,
            (const struct in6_addr*) nullptr, mk.mac_addr);

        generate_change_vlan_update(&ht_ref, p, mk.mac_addr, *hm_ptr, true);
    }
    else
    {
        hm_ptr->update_last_seen(p->pkth->ts.tv_sec);
        generate_change_host_update_eth(hm_ptr.get(), p, mk.mac_addr, packet_time());
        generate_change_vlan_update(&ht_ref, p, mk.mac_addr, *hm_ptr, false);
    }

    return 0;
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
