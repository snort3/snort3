//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort.h"
#include "protocols/arp.h"
#include "protocols/bpdu.h"
#include "protocols/cdp.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/protocol_ids.h"
#include "pub_sub/rna_events.h"

#include "rna_app_discovery.h"
#include "rna_cpe_os.h"
#include "rna_fingerprint_smb.h"
#include "rna_fingerprint_tcp.h"
#include "rna_fingerprint_udp.h"
#include "rna_flow.h"
#include "rna_logger_common.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace snort::bpdu;
using namespace snort::cdp;
using namespace snort::icmp;
using namespace std;

#define RNA_NAT_COUNT_THRESHOLD 10
#define RNA_NAT_TIMEOUT_THRESHOLD 10    // timeout in seconds

static THREAD_LOCAL HostCacheMac* local_mac_cache_ptr = nullptr;

HostCacheMac* get_host_cache_mac()
{
    return local_mac_cache_ptr;
}

void set_host_cache_mac(HostCacheMac* mac_host)
{
    local_mac_cache_ptr = mac_host;
}

HostCacheIp::Data RnaPnd::find_or_create_host_tracker(const SfIp& ip, bool& new_host)
{
    auto ht = host_cache.find_else_create(ip, &new_host);

    // If it's a new host, it's automatically visible, so we don't do anything.
    // If it's not a new host, we're rediscovering it, so make it visible.
    // Also if it was not new (we had it in the cache) and it went from
    // not visible to visible, then it's as good as new.
    if (!new_host and !ht->set_visibility(true))
    {
        ht->update_last_seen();
        new_host = true;
    }

    return ht;
}

RnaPnd::RnaPnd(const bool en, const std::string& cp, RnaConfig* rc) :
    logger(RnaLogger(en)), filter(DiscoveryFilter(cp)), conf(rc)
{
    update_timeout = (rc ? rc->update_timeout : 0);
}

RnaPnd::~RnaPnd() = default;

void RnaPnd::analyze_appid_changes(DataEvent& event)
{
    RnaAppDiscovery::process(static_cast<AppidEvent*>(&event), filter, conf, logger);
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
        if ( type == TcpPacketType::SYN and
            filter.is_host_monitored(p, nullptr, p->ptrs.ip_api.get_dst()) )
        {
            RNAFlow* rna_flow = (RNAFlow*) p->flow->get_flow_data(RNAFlow::inspector_id);
            if ( !rna_flow )
            {
                rna_flow = new RNAFlow();
                p->flow->set_flow_data(rna_flow);
            }
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

bool RnaPnd::analyze_cpe_os_info(snort::DataEvent& event)
{
    const Packet* p = event.get_packet();
    if ( !p or !p->flow )
        return false;

    RNAFlow* rna_flow = (RNAFlow*) p->flow->get_flow_data(RNAFlow::inspector_id);
    if ( !rna_flow )
        return false;

    RnaTracker rt = rna_flow->get_tracker(p, filter);
    if ( !rt )
        return false;

    CpeOsInfoEvent& cpeos_event = static_cast<CpeOsInfoEvent&>(event);
    if ( !rt->add_cpe_os_hash(cpeos_event.get_hash()) )
        return false;

    const auto& src_ip = p->ptrs.ip_api.get_src();
    const auto& src_ip_ptr = (const struct in6_addr*) src_ip->get_ip6_ptr();
    const auto& src_mac = layer::get_eth_layer(p)->ether_src;
    rt->update_last_seen();
    FpFingerprint fp = FpFingerprint();
    fp.fp_type = FpFingerprint::FpType::FP_TYPE_CPE;
    logger.log(RNA_EVENT_NEW, NEW_OS, p, &rt, src_ip_ptr, src_mac, &fp,
        cpeos_event.get_os_names(), packet_time());

    return true;
}

bool RnaPnd::analyze_netflow(snort::DataEvent& event)
{
    const Packet* p = event.get_packet();
    if ( !p )
        return false;

    NetFlowEvent* nfe = static_cast<NetFlowEvent*>(&event);

    analyze_netflow_host(nfe);

    if (nfe->get_create_service())
        analyze_netflow_service(nfe);

    return true;
}

void RnaPnd::analyze_netflow_host(NetFlowEvent* nfe)
{
    const Packet* p = nfe->get_packet();
    if ( !p )
        return;

    bool new_host = false;
    const auto& src_ip = nfe->get_record()->initiator_ip;
    const auto& src_ip_ptr = (const struct in6_addr*) src_ip.get_ip6_ptr();

    // This case must be handled first before adding the host to the
    // host cache. Otherwise, new rules evals with create_host = true
    // will fail since the host will already exist.
    if (!nfe->get_create_host() and !nfe->get_create_service())
    {
        uint32_t service = nfe->get_service_id();
        RNAEvent new_flow_event(p, nfe->get_record(), service);
        DataBus::publish(RnaConfig::pub_id, NetFlowEventIds::DATA, new_flow_event);
        return;
    }

    auto ht = find_or_create_host_tracker(src_ip, new_host);

    if ( !new_host )
        ht->update_last_seen();

    const uint8_t src_mac[6] = {0};

    if ( new_host )
    {
        if ( nfe->get_create_host() )
            logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht, src_ip_ptr, src_mac);
        else
            return;
    }

    // Note: this is the ethertype for the wire packet itself, not the NetFlow flows
    uint16_t ptype = rna_get_eth(p);
    if ( ptype > to_utype(ProtocolId::ETHERTYPE_MINIMUM) )
    {
        if ( ht->add_network_proto(ptype) )
            logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, ptype, src_mac, src_ip_ptr,
                packet_time());
    }

    // Remaining fields (port, proto, etc.) are parsed from the NetFlow record
    ptype = nfe->get_record()->proto;
    if ( ht->add_xport_proto(ptype) )
        logger.log(RNA_EVENT_NEW, NEW_XPORT_PROTOCOL, p, &ht, ptype, src_mac, src_ip_ptr,
            packet_time());

    if ( !new_host )
        generate_change_host_update(&ht, p, &src_ip, src_mac, packet_time());
}

void RnaPnd::analyze_netflow_service(NetFlowEvent* nfe)
{

    const Packet* p = nfe->get_packet();
    if ( !p )
        return;

    bool new_host = false;
    const auto& src_ip = nfe->get_record()->initiator_ip;
    const auto& mac_addr = layer::get_eth_layer(p)->ether_src;
    uint32_t service = nfe->get_service_id();
    uint16_t port = 0;
    IpProtocol proto = (IpProtocol) nfe->get_record()->proto;

    if (nfe->is_initiator_swapped())
        port = nfe->get_record()->initiator_port;
    else
        port = nfe->get_record()->responder_port;

    auto ht = find_or_create_host_tracker(src_ip, new_host);
    ht->update_last_seen();

    bool is_new = false;
    auto ha = ht->add_service(port, proto, (uint32_t) packet_time(), is_new, service);

    ht->update_service_info(ha, nullptr, nullptr, conf->max_host_service_info);

    if ( is_new )
    {
        if ( proto == IpProtocol::TCP )
            logger.log(RNA_EVENT_NEW, NEW_TCP_SERVICE, p, &ht,
                (const struct in6_addr*) src_ip.get_ip6_ptr(), mac_addr, &ha);
        else if ( proto == IpProtocol::UDP )
            logger.log(RNA_EVENT_NEW, NEW_UDP_SERVICE, p, &ht,
                (const struct in6_addr*) src_ip.get_ip6_ptr(), mac_addr, &ha);

        ha.hits = 0;
        ht->update_service(ha);
    }
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

    auto ht = find_or_create_host_tracker(*src_ip, new_host);

    uint32_t last_seen = ht->get_last_seen();
    if ( !new_host )
        ht->update_last_seen(); // this should be done always and foremost

    const auto& src_mac = layer::get_eth_layer(p)->ether_src;

    new_mac = ht->add_mac(src_mac, ttl, 0);

    RNAFlow* rna_flow = nullptr;
    if ( p->is_tcp() || p->is_udp() )
    {
        rna_flow = (RNAFlow*) p->flow->get_flow_data(RNAFlow::inspector_id);
        if ( !rna_flow )
        {
            rna_flow = new RNAFlow();
            p->flow->set_flow_data(rna_flow);
        }
        ht->add_flow(rna_flow);

        if ( p->is_from_client() )
            rna_flow->set_client(ht);
        else
            rna_flow->set_server(ht);
    }

    if ( new_host )
        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht, src_ip_ptr, src_mac);

    if ( new_mac and !new_host )
    {
        HostMac hm;

        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_ADD, p, &ht, src_ip_ptr, src_mac,
            ht->get_hostmac(src_mac, hm) ? &hm : nullptr, packet_time());
    }

    if ( ht->update_mac_ttl(src_mac, ttl) )
    {
        HostMac hm;
        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_INFO, p, &ht, src_ip_ptr, src_mac,
            ht->get_hostmac(src_mac, hm) ? &hm : nullptr, packet_time());

        if ( ht->reset_hops_if_primary() )
            logger.log(RNA_EVENT_CHANGE, CHANGE_HOPS, p, &ht, src_ip_ptr, src_mac, packet_time());
    }

    if ( p->is_tcp() and ht->get_host_type() == HOST_TYPE_HOST )
        discover_host_types_ttl(ht, p, ttl, last_seen, src_ip_ptr, src_mac);

    uint16_t ptype = rna_get_eth(p);
    if ( ptype > to_utype(ProtocolId::ETHERTYPE_MINIMUM) )
    {
        if ( ht->add_network_proto(ptype) )
            logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, ptype, src_mac, src_ip_ptr,
                packet_time());
    }

    ptype = to_utype(p->get_ip_proto_next());
    if ( ht->add_xport_proto(ptype) )
        logger.log(RNA_EVENT_NEW, NEW_XPORT_PROTOCOL, p, &ht, ptype, src_mac, src_ip_ptr,
            packet_time());

    if ( !new_host )
        generate_change_host_update(&ht, p, src_ip, src_mac, packet_time());

    discover_host_types_icmpv6_ndp(ht, p, last_seen, src_ip_ptr, src_mac);

    // Fingerprint stuff
    const TcpFpProcessor* processor;
    if ( p->is_tcp() and (processor = get_tcp_fp_processor()) != nullptr )
    {
        if ( !p->ptrs.tcph->is_syn_ack() )
            rna_flow = nullptr;
        const TcpFingerprint* tfp = processor->get(p, rna_flow);

        if ( tfp and ht->add_tcp_fingerprint(tfp->fpid) )
            logger.log(RNA_EVENT_NEW, NEW_OS, p, &ht, src_ip_ptr, src_mac, tfp, packet_time());
    }
}

void RnaPnd::analyze_dhcp_fingerprint(DataEvent& event)
{
    const Packet* p = event.get_packet();
    const auto& src_ip = p->ptrs.ip_api.get_src();
    if ( !filter.is_host_monitored(p, nullptr, src_ip) )
        return;

    const DHCPDataEvent& dhcp_data_event = static_cast<DHCPDataEvent&>(event);
    const uint8_t* src_mac = dhcp_data_event.get_eth_addr();
    bool new_host = false;
    bool new_mac = false;
    auto ht = find_or_create_host_tracker(*src_ip, new_host);
    if (!new_host)
        ht->update_last_seen();

    MacKey mk(src_mac);
    auto hm_ptr = local_mac_cache_ptr->find_else_create(mk, &new_mac);
    if (new_mac)
    {
        ht->add_mac(mk.mac_addr, p->ptrs.ip_api.ttl(), 0);
        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht, nullptr, mk.mac_addr);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }
    else
        hm_ptr->update_last_seen(p->pkth->ts.tv_sec);

    const UdpFpProcessor* processor = get_udp_fp_processor();
    if (!processor)
        return;

    FpDHCPKey key;
    key.dhcp55_len = dhcp_data_event.get_op55_len();
    key.dhcp55 = dhcp_data_event.get_op55();
    key.dhcp60_len = dhcp_data_event.get_op60_len();
    key.dhcp60 = dhcp_data_event.get_op60();

    const DHCPFingerprint* dhcp_fp = processor->match_dhcp_fingerprint(key);
    if (dhcp_fp and ht->add_udp_fingerprint(dhcp_fp->fpid))
    {
        const auto& src_ip_ptr = (const struct in6_addr*) src_ip->get_ip6_ptr();
        logger.log(RNA_EVENT_NEW, NEW_OS, p, &ht, src_ip_ptr, src_mac, dhcp_fp, packet_time());
    }
}

/* called for processing information extracted from DHCP Ack.
   It is called only for IPv4 since DHCPv6 is not implemented.*/
void RnaPnd::add_dhcp_info(DataEvent& event)
{
    const DHCPInfoEvent& dhcp_info_event = static_cast<DHCPInfoEvent&>(event);
    uint32_t ip_address = dhcp_info_event.get_ip_address();
    SfIp leased_ip = {(void*)&ip_address, AF_INET};
    const Packet* p = event.get_packet();
    if ( !filter.is_host_monitored(p, nullptr, &leased_ip) )
        return;

    const uint8_t* src_mac = dhcp_info_event.get_eth_addr();
    uint32_t net_mask = dhcp_info_event.get_subnet_mask();
    uint32_t lease = dhcp_info_event.get_lease_secs();
    uint32_t router = dhcp_info_event.get_router();

    SfIp router_ip = {(void*)&router, AF_INET};
    bool new_host = false;
    bool new_mac = false;
    auto ht = find_or_create_host_tracker(leased_ip, new_host);
    if (!new_host)
        ht->update_last_seen();

    MacKey mk(src_mac);
    auto hm_ptr = local_mac_cache_ptr->find_else_create(mk, &new_mac);
    if (new_mac)
    {
        ht->add_mac(mk.mac_addr, p->ptrs.ip_api.ttl(), 0);
        logger.log(RNA_EVENT_NEW, NEW_HOST, p, &ht, nullptr, mk.mac_addr);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }
    else
        hm_ptr->update_last_seen(p->pkth->ts.tv_sec);

    logger.log(RNA_EVENT_CHANGE, CHANGE_FULL_DHCP_INFO, p, &ht,
        (const struct in6_addr*) leased_ip.get_ip6_ptr(), src_mac,
        lease, net_mask, (const struct in6_addr*) router_ip.get_ip6_ptr());
}

void RnaPnd::analyze_smb_fingerprint(DataEvent& event)
{
    const SmbFpProcessor* processor = get_smb_fp_processor();
    if (!processor)
        return;

    const Packet* p = event.get_packet();
    RNAFlow* rna_flow = (RNAFlow*) p->flow->get_flow_data(RNAFlow::inspector_id);
    if ( !rna_flow )
        return;

    RnaTracker rt = rna_flow->get_tracker(p, filter);
    if ( !rt )
        return;

    const FpSMBDataEvent& fp_smb_data_event = static_cast<FpSMBDataEvent&>(event);
    unsigned smb_major = fp_smb_data_event.get_fp_smb_major();
    unsigned smb_minor = fp_smb_data_event.get_fp_smb_minor();
    uint32_t flags = fp_smb_data_event.get_fp_smb_flags();

    const SmbFingerprint* fp = processor->find({smb_major, smb_minor, flags});

    if ( fp && rt->add_smb_fingerprint(fp->fpid) )
    {
        const auto& src_ip = p->ptrs.ip_api.get_src();
        const auto& src_ip_ptr = (const struct in6_addr*) src_ip->get_ip6_ptr();
        const auto& src_mac = layer::get_eth_layer(p)->ether_src;

        logger.log(RNA_EVENT_NEW, NEW_OS, p, &rt, src_ip_ptr, src_mac, fp, packet_time());
    }
}

inline void RnaPnd::update_vlan(const Packet* p, HostTrackerMac& hm)
{
    if ( !(p->proto_bits & PROTO_BIT__VLAN) )
        return;

    const vlan::VlanTagHdr* vh = layer::get_vlan_layer(p);

    if ( vh )
        hm.update_vlan(vh->vth_pri_cfi_vlan, vh->vth_proto);
}

void RnaPnd::generate_change_vlan_update(RnaTracker *rt, const Packet* p,
    const uint8_t* src_mac, HostTrackerMac& hm, bool isnew)
{
    if ( !(p->proto_bits & PROTO_BIT__VLAN) )
        return;

    const vlan::VlanTagHdr* vh = layer::get_vlan_layer(p);

    if ( !vh )
        return;

    if ( isnew or !hm.has_same_vlan(vh->vth_pri_cfi_vlan) )
    {
        if ( !isnew )
            update_vlan(p, hm);

        rt->get()->update_vlan(vh->vth_pri_cfi_vlan, vh->vth_proto);
        logger.log(RNA_EVENT_CHANGE, CHANGE_VLAN_TAG, p, rt, nullptr, src_mac, packet_time());
    }
}

void RnaPnd::generate_change_vlan_update(RnaTracker *rt, const Packet* p,
    const uint8_t* src_mac, const SfIp* src_ip, bool isnew)
{
    if ( !(p->proto_bits & PROTO_BIT__VLAN) )
        return;

    const vlan::VlanTagHdr* vh = layer::get_vlan_layer(p);
    if ( !vh )
        return;

    if ( isnew or !rt->get()->has_same_vlan(vh->vth_pri_cfi_vlan) )
    {
        rt->get()->update_vlan(vh->vth_pri_cfi_vlan, vh->vth_proto);
        logger.log(RNA_EVENT_CHANGE, CHANGE_VLAN_TAG, p, rt,
            (const struct in6_addr*) src_ip->get_ip6_ptr(), src_mac, packet_time());
    }
}

void RnaPnd::generate_change_host_update(RnaTracker* ht, const Packet* p,
    const SfIp* src_ip, const uint8_t* src_mac, const time_t& sec)
{
    if ( !ht or !update_timeout )
        return;

    uint32_t last_seen = (*ht)->get_last_seen();
    uint32_t last_event = (*ht)->get_last_event();
    time_t timestamp = sec - update_timeout;
    if ( last_seen > last_event and (time_t) last_event + update_timeout <= sec )
        logger.log(RNA_EVENT_CHANGE, CHANGE_HOST_UPDATE, p, src_mac,
            (const struct in6_addr*) src_ip->get_ip6_ptr(), ht, last_seen, (void*) &timestamp);
    // FIXIT-M: deal with host service hits.
}


void RnaPnd::generate_change_host_update_eth(HostTrackerMac* mt, const Packet* p,
    const uint8_t* src_mac, const time_t& sec)
{
    if ( !mt or !update_timeout)
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

    if ( last_seen > last_event and (time_t) last_event + update_timeout <= sec )
    {
        logger.log(RNA_EVENT_CHANGE, CHANGE_HOST_UPDATE, p, src_mac, nullptr,
            &rt, last_seen, (void*) &timestamp);

        mt->update_last_event(sec);
    }

}

void RnaPnd::generate_change_host_update()
{
    if ( !update_timeout )
        return;

    auto hosts = host_cache.get_all_data();
    auto mac_hosts = local_mac_cache_ptr->get_all_data();
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

    auto hm_ptr = local_mac_cache_ptr->find_else_create(mk, &new_host_mac);

    if ( new_host_mac )
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

    if ( discover_proto )
    {
        uint16_t ntype = rna_get_eth(p);
        if ( ntype > to_utype(ProtocolId::ETHERTYPE_MINIMUM) )
        {
            if ( hm_ptr->add_network_proto(ntype) )
            {
                logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, ntype, mk.mac_addr);
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
                    logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, ntype, mk.mac_addr);
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

    if ( !p->is_eth() )
        return;

    RnaTracker rt = shared_ptr<snort::HostTracker>(new HostTracker());

    if ( layer::get_arp_layer(p) )
        retval = discover_network_arp(p, &rt);
    else
    {
        // If we have an inner LLC layer, grab it
        const Layer& lyr = p->layers[p->num_layers-1];
        if ( lyr.prot_id == ProtocolId::ETHERNET_LLC )
        {
            uint16_t etherType = rna_get_eth(p);

            if ( !etherType or etherType > static_cast<uint16_t>(ProtocolId::ETHERTYPE_MINIMUM) )
            {
                generate_new_host_mac(p, rt);
                return;
            }

            const RNA_LLC* llc = (const RNA_LLC*) lyr.start;

            if ( llc->s.s.DSAP != llc->s.s.SSAP )
            {
                generate_new_host_mac(p, rt);
                return;
            }

            switch ( llc->s.s.DSAP )
            {
            case BPDU_ID:
                retval = discover_network_bpdu(p, ((const uint8_t*)llc + sizeof(RNA_LLC)), rt);
                break;

            case SNAP_ID:
                retval = discover_network_cdp(p, (const uint8_t*)llc + sizeof(RNA_LLC),
                    p->dsize - sizeof(RNA_LLC), rt);
                break;

            default:
                break;
            }
        }
    }

    if ( retval )
        generate_new_host_mac(p, rt, true);

    return;
}

int RnaPnd::discover_network_arp(const Packet* p, RnaTracker* ht_ref)
{
    MacKey mk(layer::get_eth_layer(p)->ether_src);
    const auto& src_mac = mk.mac_addr;

    const snort::arp::EtherARP *ah = layer::get_arp_layer(p);

    if ( ntohs(ah->ea_hdr.ar_hrd) != 0x0001 )
        return 1;
    if ( ntohs(ah->ea_hdr.ar_pro) != 0x0800 )
        return 1;
    if ( ah->ea_hdr.ar_hln != 6 or ah->ea_hdr.ar_pln != 4 )
        return 1;
    if ( (ntohs(ah->ea_hdr.ar_op) != 0x0002) )
        return 1;
    if ( memcmp(src_mac, ah->arp_sha, MAC_SIZE) )
        return 1;
    if ( !ah->arp_spa32 )
        return 1;

    SfIp spa(ah->arp_spa, AF_INET);

    // In the case where SPA is not monitored, log as a generic "NEW MAC"
    if ( !filter.is_host_monitored(p, nullptr, &spa) )
        return 1;

    bool new_host = false;
    bool new_host_mac = false;
    auto ht = find_or_create_host_tracker(spa, new_host);

    auto hm_ptr = local_mac_cache_ptr->find_else_create(mk, &new_host_mac);

    if ( !new_host_mac )
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
        HostMac hm;
        HostMac* phm = nullptr;
        if ( ht->get_hostmac(src_mac, hm) )
            phm = &hm;

        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_ADD, p, ht_ref,
            (const struct in6_addr*) spa.get_ip6_ptr(), src_mac, phm);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }
    else if ( ht->make_primary(src_mac) )
    {
        HostMac hm;
        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_INFO, p, ht_ref,
            (const struct in6_addr*) spa.get_ip6_ptr(), src_mac,
            ht->get_hostmac(src_mac, hm) ? &hm : nullptr);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }

    generate_change_vlan_update(&ht, p, src_mac, &spa, true);
    auto ntype = to_utype(ProtocolId::ETHERTYPE_ARP);

    if ( hm_ptr->add_network_proto(ntype) )
    {
        logger.log(RNA_EVENT_NEW, NEW_NET_PROTOCOL, p, &ht, ntype, src_mac);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }

    if ( ht->get_hops() )
    {
        HostMac hm;

        ht->update_hops(0);
        logger.log(RNA_EVENT_CHANGE, CHANGE_HOPS, p, ht_ref,
            (const struct in6_addr*) spa.get_ip6_ptr(), src_mac, ht->get_hostmac(src_mac, hm) ? &hm : nullptr);
        hm_ptr->update_last_event(p->pkth->ts.tv_sec);
    }

    if ( !new_host )
        generate_change_host_update_eth(hm_ptr.get(), p, src_mac, packet_time());

    return 0;
}

int RnaPnd::discover_network_bpdu(const Packet* p, const uint8_t* data, RnaTracker ht_ref)
{
    const uint8_t* dst_mac = layer::get_eth_layer(p)->ether_dst;

    const BPDUData* stp;

    if ( !isBPDU(dst_mac) )
        return 1;
    stp = reinterpret_cast<const BPDUData*>(data);
    if ( stp->id or stp->version )
        return 1;
    if ( stp->type !=  BPDU_TYPE_TOPCHANGE )
        return 1;

    return discover_switch(p, ht_ref);
}

int RnaPnd::discover_switch(const Packet* p, RnaTracker ht_ref)
{
    bool new_host_mac = false;
    MacKey mk(layer::get_eth_layer(p)->ether_src);

    auto hm_ptr = local_mac_cache_ptr->find_else_create(mk, &new_host_mac);

    if ( new_host_mac )
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

void RnaPnd::discover_host_types_ttl(RnaTracker& ht, const Packet *p, uint8_t pkt_ttl,
    uint32_t last_seen, const struct in6_addr* src_ip, const uint8_t* src_mac)
{
    uint8_t ht_ttl = ht->get_ip_ttl();
    if ( pkt_ttl and ht_ttl and (pkt_ttl != ht_ttl) )
    {
        if ( (abs(ht_ttl - pkt_ttl) > MIN_TTL_DIFF) )
        {
            uint32_t ht_last_seen = ht->get_last_seen();
            if ( ht_last_seen < (last_seen + MIN_BOOT_TIME) )
            {
                uint32_t nc = ht->inc_nat_count();
                if ( nc >= RNA_NAT_COUNT_THRESHOLD )
                {
                    ht->set_nat_count(0);
                    if ( ht_last_seen - ht->get_nat_count_start() <= RNA_NAT_TIMEOUT_THRESHOLD )
                    {
                        ht->set_host_type(p->is_from_application_client() ? HOST_TYPE_NAT : HOST_TYPE_LB);
                        logger.log(RNA_EVENT_CHANGE, CHANGE_HOST_TYPE, p, &ht, src_ip, src_mac);
                    }

                    ht->set_nat_count_start(ht_last_seen);
                }
            }
        }
    }

    ht->set_ip_ttl(pkt_ttl);
}

int RnaPnd::discover_network_cdp(const Packet* p, const uint8_t* data, uint16_t rlen,
    RnaTracker& rt)
{
    if ( !is_cdp(layer::get_eth_layer(p)->ether_dst) or rlen < sizeof(RNA_CDP) )
        return 1;

    if ( ntohs(((const RNA_CDP *)data)->pid) != CDP_HDLC_PROTOCOL_TYPE )
        return 1;

    generate_new_host_mac(p, rt, true);

    data += sizeof(RNA_CDP);
    const uint8_t* end = data + rlen - sizeof(RNA_CDP);
    std::vector<uint32_t> ip_address;
    uint32_t cap = 0;
    while ( data < end )
    {
        uint16_t len;
        uint16_t type;
        const RNA_CDP_DATA* tlv;

        tlv = (const RNA_CDP_DATA *)data;
        len = ntohs(tlv->length);
        if ( len < sizeof(RNA_CDP_DATA) or data + len > end )
            return 1;

        type = ntohs(tlv->type);
        if ( type == RNA_CDP_ADDRESS_TYPE )
        {
            uint16_t addr_len = len - sizeof(RNA_CDP_DATA);
            uint32_t num_addrs;

            data += sizeof(RNA_CDP_DATA);
            num_addrs = ntohl(*((const uint32_t *)data));
            data += sizeof(uint32_t);
            addr_len -= sizeof(uint32_t);
            for (unsigned i = 0; i < num_addrs; i++)
            {
                uint16_t tmp_len;
                bool ip;

                if (addr_len < 5)
                    return 1;

                ip = ( *data == 0x01 ) ? true : false;
                data++;
                addr_len--;
                ip = ( ip and (*data == 0x01) ) ? true : false;
                tmp_len = *data;
                data++;
                addr_len--;
                ip = ( ip and (*data == 0xcc) ) ? true : false;
                data += tmp_len;
                addr_len -= tmp_len;

                if ( addr_len < 2 )
                    return 1;

                tmp_len = ntohs(*((const uint16_t *)data));
                data += sizeof(uint16_t);
                addr_len -= sizeof(uint16_t);

                if ( addr_len < tmp_len )
                    return 1;

                if (ip and tmp_len == 0x0004)
                    ip_address.push_back(*((const uint32_t *)data));

                data += tmp_len;
                addr_len -= tmp_len;
            }

            if ( addr_len )
                return 1;
        }
        else if ( type == RNA_CDP_CAPABILITIES_TYPE )
        {
            data += sizeof(RNA_CDP_DATA);
            if ( len != 8 )
                return 1;
            cap = ntohl(*((const uint32_t *)data));
            data += sizeof(uint32_t);
        }
        else
            data += len;
    }

    if ( !(cap & RNA_CDP_CAPABILITIES_MASK) )
        return 0;

    for ( uint32_t a : ip_address )
    {
        SfIp cdp_ip = {(void*)&a, AF_INET};
        auto ht = host_cache.find(cdp_ip);

        if ( ht and (ht->get_host_type() == HOST_TYPE_HOST) )
        {
            if ( cap & RNA_CDP_CAPABILITIES_ROUTER )
                ht->set_host_type(HOST_TYPE_ROUTER);
            else
                ht->set_host_type(HOST_TYPE_BRIDGE);

            logger.log(RNA_EVENT_CHANGE, CHANGE_HOST_TYPE, p, &ht,
                (const struct in6_addr*)cdp_ip.get_ip6_ptr(), layer::get_eth_layer(p)->ether_src);
        }
    }

    return 0;
}

int RnaPnd::discover_host_types_icmpv6_ndp(RnaTracker& ht, const Packet* p, uint32_t last_seen,
    const struct in6_addr* src_ip, const uint8_t* src_mac)
{
    const uint8_t* neighbor_src_mac = nullptr;
    bool is_router = false;

    if ( !p->is_icmp() or !p->is_ip6() )
        return 1;

    const uint8_t* data = (const uint8_t*)p->ptrs.icmph;
    int32_t data_len = p->ptrs.ip_api.pay_len();

    switch ( ((const icmp::Icmp6Hdr*)p->ptrs.icmph)->type )
    {
        case snort::icmp::NEIGHBOR_ADVERTISEMENT:
            if ( (p->ptrs.icmph->code) or (data_len <= ICMPv6_NA_MIN_LEN) )
                return 1;

            data += ICMPv6_NA_MIN_LEN;
            data_len -= ICMPv6_NA_MIN_LEN;

            while ( data_len >= 2 )
            {
                uint8_t opt_type = *data;
                if ( opt_type == ICMPV6_OPTION_TARGET_LINKLAYER_ADDRESS )
                    neighbor_src_mac = data + 2;

                uint8_t opt_len = *(data + 1);
                if ( opt_len == 0 )
                    break;
                data += opt_len * 8;
                data_len -= opt_len * 8;
            }
            break;

        case snort::icmp::ROUTER_ADVERTISEMENT:
            if ( p->ptrs.icmph->code or (data_len <= ICMPv6_RA_MIN_LEN) )
                return 1;

            is_router = true;
            data += ICMPv6_RA_MIN_LEN;
            data_len -= ICMPv6_RA_MIN_LEN;

            while ( data_len >= 2 )
            {
                uint8_t opt_type = *data;
                if ( opt_type == ICMPV6_OPTION_SOURCE_LINKLAYER_ADDRESS )
                    neighbor_src_mac = data + 2;

                uint8_t opt_len = *(data + 1);
                if ( opt_len == 0 )
                    break;
                data += opt_len * 8;
                data_len -= opt_len * 8;
            }
            break;

        case snort::icmp::ROUTER_SOLICITATION:
        case snort::icmp::NEIGHBOR_SOLICITATION:
        default:
            return 1;
    }

    if ( data_len or !neighbor_src_mac )
        return 1;

    // discarding packets through arp proxy.
    if ( memcmp(src_mac, neighbor_src_mac, MAC_SIZE) )
        return 1;

    if ( is_router )
    {
        auto host_type = ht->get_host_type();
        if ( host_type != HOST_TYPE_ROUTER and host_type != HOST_TYPE_BRIDGE )
        {
            ht->set_host_type(HOST_TYPE_ROUTER);
            logger.log(RNA_EVENT_CHANGE, CHANGE_HOST_TYPE, p, &ht, src_ip, neighbor_src_mac);
        }
    }

    if ( ht->make_primary(src_mac) )
    {
        HostMac hm;
        logger.log(RNA_EVENT_CHANGE, CHANGE_MAC_INFO, p, &ht,
            src_ip, src_mac, ht->get_hostmac(src_mac, hm) ? &hm : nullptr, last_seen);
    }

    return 1;
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

TEST_CASE("RNA pnd cpe os", "[cpe-os]")
{
    SECTION("Testing new os RNA event for cpe os")
    {
        RNAFlow::init();
        RNAFlow* rna_flow = new RNAFlow();
        Packet p;
        Flow flow;
        p.flow = &flow;
        p.flow->set_flow_data(rna_flow);

        // Fill packet structure with required information
        eth::EtherHdr eh;
        const char mac[6] = { 00, 01, 02, 03, 04, 05 };
        ip::IP4Hdr h4;
        h4.ip_src = 0x65010101;
        h4.ip_dst = 0x65010102;
        p.ptrs.ip_api.set(&h4);
        memcpy(eh.ether_src, mac, MAC_SIZE);
        p.packet_flags = PKT_FROM_CLIENT;
        p.num_layers = 1;
        p.layers[0].start = (const uint8_t*) &eh;

        // Setup host tracker and attach it to rna flow as client
        auto* src_ip = p.ptrs.ip_api.get_src();
        bool new_host = false;

        RnaPnd pnd(false, "");

        Packet p2;
        p2.flow = nullptr;

        // Test to hit sanity check ht is null
        CpeOsInfoEvent* cpeevent = new CpeOsInfoEvent(p2);
        cpeevent->add_os("CPE OS one");
        CHECK(pnd.analyze_cpe_os_info(*cpeevent) == false);
        delete(cpeevent);
        cpeevent = new CpeOsInfoEvent(p);
        cpeevent->add_os("CPE OS one");
        CHECK(pnd.analyze_cpe_os_info(*cpeevent) == false);

        // Check new OS information is invoking logging
        auto ht = host_cache.find_else_create(*src_ip, &new_host);
        rna_flow->set_client(ht);
        CHECK(pnd.analyze_cpe_os_info(*cpeevent) == true);

        // Check duplicate OS information is not invoking logging
        CHECK(pnd.analyze_cpe_os_info(*cpeevent) == false);
        delete(cpeevent);

        // Check second OS information is invoking logging
        cpeevent = new CpeOsInfoEvent(p);
        cpeevent->add_os("CPE OS two");
        CHECK(pnd.analyze_cpe_os_info(*cpeevent) == true);

        // Again check duplicate OS information is not invoking logging
        CHECK(pnd.analyze_cpe_os_info(*cpeevent) == false);

        delete(cpeevent);
        p.flow->free_flow_data(rna_flow);
    }
}
#endif
