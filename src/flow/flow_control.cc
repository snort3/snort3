/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#include "flow/flow_control.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <arpa/inet.h>

#include "flow/flow_cache.h"
#include "flow/expect_cache.h"
#include "flow/session.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "utils/stats.h"
#include "protocols/layer.h"
#include "protocols/vlan.h"
#include "managers/inspector_manager.h"
#include "sfip/sf_ip.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"

FlowControl::FlowControl()
{
    ip_cache = nullptr;
    icmp_cache = nullptr;
    tcp_cache = nullptr;
    udp_cache = nullptr;
    exp_cache = nullptr;
}

FlowControl::~FlowControl()
{
    delete tcp_cache;
    delete udp_cache;
    delete icmp_cache;
    delete ip_cache;
    delete exp_cache;
}

//-------------------------------------------------------------------------
// count foo
//-------------------------------------------------------------------------

static THREAD_LOCAL PegCount tcp_count = 0;
static THREAD_LOCAL PegCount udp_count = 0;
static THREAD_LOCAL PegCount icmp_count = 0;
static THREAD_LOCAL PegCount ip_count = 0;

PegCount FlowControl::get_flow_count(uint8_t proto)
{
    switch ( proto )
    {
    case IPPROTO_TCP:  return tcp_count;
    case IPPROTO_UDP:  return udp_count;
    case IPPROTO_ICMP: return icmp_count;
    case IPPROTO_IP:   return ip_count;
    default:            return 0;
    }
}

void FlowControl::clear_flow_counts()
{
    tcp_count = udp_count = 0;
    icmp_count = ip_count = 0;
}

//-------------------------------------------------------------------------
// cache foo
//-------------------------------------------------------------------------

inline FlowCache* FlowControl::get_cache (uint8_t proto)
{
    switch ( proto )
    {
    case IPPROTO_TCP:    return tcp_cache;
    case IPPROTO_UDP:    return udp_cache;
    case IPPROTO_ICMP:   return icmp_cache;
    case IPPROTO_IP:     return ip_cache;
    default:              return nullptr;
    }
}

Flow* FlowControl::find_flow (const FlowKey* key)
{
    FlowCache* cache = get_cache(key->protocol);

    if ( cache )
        return cache->find(key);

    return NULL;
}

Flow* FlowControl::new_flow (const FlowKey* key)
{
    FlowCache* cache = get_cache(key->protocol);

    if ( !cache )
        return NULL;

    return cache->get(key);
}

// FIXIT-L cache* can be put in flow so that lookups by
// protocol are obviated for existing / initialized flows
void FlowControl::delete_flow (const FlowKey* key)
{
    FlowCache* cache = get_cache(key->protocol);

    if ( !cache )
        return;

    Flow* flow = cache->find(key);

    if ( flow )
        cache->release(flow, "ha sync");
}

void FlowControl::delete_flow (Flow* flow, const char* why)
{
    FlowCache* cache = get_cache(flow->ip_proto);

    if ( cache )
        cache->release(flow, why);
}

void FlowControl::purge_flows (uint8_t proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        cache->purge();
}

void FlowControl::prune_flows (uint8_t proto, Packet* p)
{
    FlowCache* cache = get_cache(proto);

    if ( !cache )
        return;

    // smack the older timed out flows
    if (!cache->prune_stale(p->pkth->ts.tv_sec, (Flow*)p->flow))
    {
        // if no luck, try the memcap
        cache->prune_excess(true, (Flow*)p->flow);
    }
}

void FlowControl::timeout_flows(uint32_t flowCount, time_t cur_time)
{
    Active_Suspend();

    if ( tcp_cache )
        tcp_cache->timeout(flowCount, cur_time);

    if ( udp_cache )
        udp_cache->timeout(flowCount, cur_time);

    //if ( icmp_cache )
    //icmp_cache does not need cleaning

    if ( ip_cache )
        ip_cache->timeout(flowCount, cur_time);

    Active_Resume();
}

uint32_t FlowControl::max_flows(uint8_t proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        return cache->get_max_flows();

    return 0;
}

void FlowControl::get_prunes (uint8_t proto, PegCount& prunes)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        prunes = cache->get_prunes();
}

void FlowControl::reset_prunes (uint8_t proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        cache->reset_prunes();
}

//-------------------------------------------------------------------------
// packet foo
//-------------------------------------------------------------------------

void FlowControl::set_key(FlowKey* key, Packet* p)
{
    const ip::IpApi& ip_api = p->ptrs.ip_api;
    uint32_t mplsId;
    uint16_t vlanId;
    uint16_t addressSpaceId;
    uint8_t proto = p->get_ip_proto_next();

    if ( p->proto_bits & PROTO_BIT__VLAN )
        vlanId = layer::get_vlan_layer(p)->vid();
    else
        vlanId = 0;

    if ( p->proto_bits & PROTO_BIT__MPLS )
        mplsId = p->ptrs.mplsHdr.label;
    else
        mplsId = 0;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    addressSpaceId = DAQ_GetAddressSpaceID(p->pkth);
#else
    addressSpaceId = 0;
#endif

    if ( (p->ptrs.decode_flags & DECODE_FRAG) )
    {
        key->init(ip_api.get_src(), ip_api.get_dst(), ip_api.id(),
            proto, vlanId, mplsId, addressSpaceId);
    }
    else if (proto == IPPROTO_ICMP)
    {
        key->init(ip_api.get_src(), p->ptrs.icmph->type, ip_api.get_dst(), 0,
            proto, vlanId, mplsId, addressSpaceId);
    }
    else
    {
        key->init(ip_api.get_src(), p->ptrs.sp, ip_api.get_dst(), p->ptrs.dp,
                  proto, vlanId, mplsId, addressSpaceId);
    }

}

static bool is_bidirectional(const Flow* flow)
{
    constexpr unsigned bidir = SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER;
    return (flow->s5_state.session_flags & bidir) == bidir;
}

// FIXIT-L init_roles* should take const Packet*
static void init_roles_tcp(Packet* p, Flow* flow)
{
    if ( p->ptrs.tcph->is_syn_only() )
    {
        flow->s5_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else if ( p->ptrs.tcph->is_syn_ack() )
    {
        flow->s5_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
    else if (p->ptrs.sp > p->ptrs.dp)
    {
        flow->s5_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else
    {
        flow->s5_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
}

static void init_roles_udp(Packet* p, Flow* flow)
{
    flow->s5_state.direction = FROM_SENDER;
    sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
    flow->client_port = ntohs(p->ptrs.udph->uh_sport);
    sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
    flow->server_port = ntohs(p->ptrs.udph->uh_dport);
}

static void init_roles(Packet* p, Flow* flow)
{
    if ( flow->protocol == PktType::TCP )
        init_roles_tcp(p, flow);

    else if ( flow->protocol == PktType::UDP )
        init_roles_udp(p, flow);
}

unsigned FlowControl::process(FlowCache* cache, Packet* p)
{
    unsigned news = 0;
    FlowKey key;
    set_key(&key, p);

    Flow* flow = cache->get(&key);

    if ( !flow )
        return 0;

    p->flow = flow;

    if ( flow->flow_state )
        set_policies(snort_conf, flow->policy_id);

    else
    {
        init_roles(p, flow);
        Inspector* b = InspectorManager::get_binder();
        if ( b )
            b->eval(p);
        ++news;
    }

    switch ( flow->flow_state )
    {
    case 1: // block
        stream.drop_packet(p);
        flow->flow_state = 1;
        break;

    case 2: // allow
        stream.stop_inspection(flow, p, SSN_DIR_BOTH, -1, 0);
        break;

    case 3: // setup
        if ( !flow->ssn_client || !flow->session->setup(p) )
        {
            flow->flow_state = 2;
            break;
        }
        flow->flow_state = 4;
        // now process

    case 4: // inspect
        assert(flow->ssn_client);
        assert(flow->ssn_server);
        flow->session->process(p);
        break;
    }

    if ( flow->next && is_bidirectional(flow) )
        cache->unlink_uni(flow);

    return news;
}

//-------------------------------------------------------------------------
// tcp
//-------------------------------------------------------------------------

void FlowControl::init_tcp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions )
    {
        tcp_cache = nullptr;
        return;
    }
    tcp_cache = new FlowCache(
        fc.max_sessions, fc.cache_pruning_timeout,
        fc.cache_nominal_timeout, 5, 0);

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
    {
        Flow* flow = new Flow(PktType::TCP);
        flow->session = get_ssn(flow);
        tcp_cache->push(flow);
    }
}

void FlowControl::process_tcp(Packet* p)
{
    if ( !tcp_cache )
        return;

    tcp_count += process(tcp_cache, p);
}

//-------------------------------------------------------------------------
// udp
//-------------------------------------------------------------------------

void FlowControl::init_udp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions )
    {
        udp_cache = nullptr;
        return;
    }
    udp_cache = new FlowCache(
        fc.max_sessions, fc.cache_pruning_timeout,
        fc.cache_nominal_timeout, 5, 0);

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
    {
        Flow* flow = new Flow(PktType::UDP);
        flow->session = get_ssn(flow);
        udp_cache->push(flow);
    }
}

void FlowControl::process_udp(Packet* p)
{
    if ( !udp_cache )
        return;

    udp_count += process(udp_cache, p);
}

//-------------------------------------------------------------------------
// icmp
//-------------------------------------------------------------------------

void FlowControl::init_icmp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions )
    {
        icmp_cache = nullptr;
        return;
    }
    icmp_cache = new FlowCache(
        fc.max_sessions, fc.cache_pruning_timeout,
        fc.cache_nominal_timeout, 5, 0);

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
    {
        Flow* flow = new Flow(PktType::ICMP);
        flow->session = get_ssn(flow);
        icmp_cache->push(flow);
    }
}

void FlowControl::process_icmp(Packet* p)
{
    if ( icmp_cache )
        icmp_count += process(icmp_cache, p);

    else
        process_ip(p);
}

//-------------------------------------------------------------------------
// ip
//-------------------------------------------------------------------------

void FlowControl::init_ip(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions )
    {
        ip_cache = nullptr;
        return;
    }
    ip_cache = new FlowCache(
        fc.max_sessions, fc.cache_pruning_timeout,
        fc.cache_nominal_timeout, 5, 0);

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
    {
        Flow* flow = new Flow(PktType::IP);
        flow->session = get_ssn(flow);
        ip_cache->push(flow);
    }
}

void FlowControl::process_ip(Packet* p)
{
    if ( !ip_cache )
        return;

    ip_count += process(ip_cache, p);
}

//-------------------------------------------------------------------------
// expected
//-------------------------------------------------------------------------

void FlowControl::init_exp(
    const FlowConfig& tcp, const FlowConfig& udp)
{
    uint32_t max = tcp.max_sessions + udp.max_sessions;
    max >>= 9;

    if ( !max )
        max = 2;

    exp_cache = new ExpectCache(max);
}

char FlowControl::expected_flow (Flow* flow, Packet* p)
{
    char ignore = exp_cache->check(p, flow);

    if ( ignore )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Ignoring packet from %d. Marking flow marked as ignore.\n",
            p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););

        flow->s5_state.ignore_direction = ignore;
        DisableInspection(p);
    }

    return ignore;
}

int FlowControl::add_expected(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    uint8_t protocol, char direction,
    FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, direction, fd);
}

int FlowControl::add_expected(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    uint8_t protocol, int16_t appId,
    FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, SSN_DIR_BOTH, fd, appId);
}

bool FlowControl::is_expected(Packet* p)
{
    return exp_cache->is_expected(p);
}

