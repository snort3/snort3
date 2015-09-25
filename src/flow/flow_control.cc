//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
#include "detection/detect.h"

FlowControl::FlowControl()
{
    ip_cache = nullptr;
    icmp_cache = nullptr;
    tcp_cache = nullptr;
    udp_cache = nullptr;
    user_cache = nullptr;
    file_cache = nullptr;
    exp_cache = nullptr;

    ip_mem = icmp_mem = nullptr;
    tcp_mem = udp_mem = nullptr;
    user_mem = file_mem = nullptr;

    get_ip = get_icmp = nullptr;
    get_tcp = get_udp = nullptr;
    get_user = get_file = nullptr;
}

FlowControl::~FlowControl()
{
    delete ip_cache;
    delete icmp_cache;
    delete tcp_cache;
    delete udp_cache;
    delete user_cache;
    delete file_cache;
    delete exp_cache;

    free(ip_mem);
    free(icmp_mem);
    free(tcp_mem);
    free(udp_mem);
    free(user_mem);
    free(file_mem);
}

//-------------------------------------------------------------------------
// count foo
//-------------------------------------------------------------------------

static THREAD_LOCAL PegCount ip_count = 0;
static THREAD_LOCAL PegCount icmp_count = 0;
static THREAD_LOCAL PegCount tcp_count = 0;
static THREAD_LOCAL PegCount udp_count = 0;
static THREAD_LOCAL PegCount user_count = 0;
static THREAD_LOCAL PegCount file_count = 0;

uint32_t FlowControl::max_flows(PktType proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        return cache->get_max_flows();

    return 0;
}

PegCount FlowControl::get_prunes (PktType proto)
{
    FlowCache* cache = get_cache(proto);
    return cache ? cache->get_prunes() : 0;
}

PegCount FlowControl::get_flows(PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return ip_count;
    case PktType::ICMP: return icmp_count;
    case PktType::TCP:  return tcp_count;
    case PktType::UDP:  return udp_count;
    case PktType::PDU: return user_count;
    case PktType::FILE: return file_count;
    default:            return 0;
    }
}

void FlowControl::clear_counts()
{
    ip_count = icmp_count = 0;
    tcp_count = udp_count = 0;
    user_count = file_count = 0;

    FlowCache* cache;

    if ( (cache = get_cache(PktType::IP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::ICMP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::TCP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::UDP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::PDU)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::FILE)) )
        cache->reset_prunes();
}

Memcap& FlowControl::get_memcap (PktType proto)
{
    static Memcap dummy;
    FlowCache* cache = get_cache(proto);
    assert(cache);  // FIXIT-L dummy is a hack
    return cache ? cache->get_memcap() : dummy;
}

//-------------------------------------------------------------------------
// cache foo
//-------------------------------------------------------------------------

inline FlowCache* FlowControl::get_cache (PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return ip_cache;
    case PktType::ICMP: return icmp_cache;
    case PktType::TCP:  return tcp_cache;
    case PktType::UDP:  return udp_cache;
    case PktType::PDU: return user_cache;
    case PktType::FILE: return file_cache;
    default:            return nullptr;
    }
}

Flow* FlowControl::find_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache((PktType)key->protocol);

    if ( cache )
        return cache->find(key);

    return NULL;
}

Flow* FlowControl::new_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache((PktType)key->protocol);

    if ( !cache )
        return NULL;

    return cache->get(key);
}

// FIXIT-L cache* can be put in flow so that lookups by
// protocol are obviated for existing / initialized flows
void FlowControl::delete_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache((PktType)key->protocol);

    if ( !cache )
        return;

    Flow* flow = cache->find(key);

    if ( flow )
        cache->release(flow, "ha sync");
}

void FlowControl::delete_flow(Flow* flow, const char* why)
{
    FlowCache* cache = get_cache(flow->protocol);

    if ( cache )
        cache->release(flow, why);
}

void FlowControl::purge_flows (PktType proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        cache->purge();
}

void FlowControl::prune_flows (PktType proto, Packet* p)
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
    Active::suspend();

    if ( ip_cache )
        ip_cache->timeout(flowCount, cur_time);

    //if ( icmp_cache )
    //icmp_cache does not need cleaning

    if ( tcp_cache )
        tcp_cache->timeout(flowCount, cur_time);

    if ( udp_cache )
        udp_cache->timeout(flowCount, cur_time);

    if ( user_cache )
        user_cache->timeout(flowCount, cur_time);

    if ( file_cache )
        file_cache->timeout(flowCount, cur_time);

    Active::resume();
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
    uint8_t type = (uint8_t)p->type();
    uint8_t proto = (uint8_t)p->get_ip_proto_next();

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
        key->init(type, proto, ip_api.get_src(), ip_api.get_dst(), ip_api.id(),
            vlanId, mplsId, addressSpaceId);
    }
    else if ( type == (uint8_t)PktType::ICMP )
    {
        key->init(type, proto, ip_api.get_src(), p->ptrs.icmph->type, ip_api.get_dst(), 0,
            vlanId, mplsId, addressSpaceId);
    }
    else
    {
        key->init(type, proto, ip_api.get_src(), p->ptrs.sp, ip_api.get_dst(), p->ptrs.dp,
            vlanId, mplsId, addressSpaceId);
    }
}

static bool is_bidirectional(const Flow* flow)
{
    constexpr unsigned bidir = SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER;
    return (flow->ssn_state.session_flags & bidir) == bidir;
}

// FIXIT-L init_roles* should take const Packet*
static void init_roles_ip(Packet* p, Flow* flow)
{
    flow->ssn_state.direction = FROM_CLIENT;
    sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
    sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
}

static void init_roles_tcp(Packet* p, Flow* flow)
{
    if ( p->ptrs.tcph->is_syn_only() )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else if ( p->ptrs.tcph->is_syn_ack() )
    {
        flow->ssn_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
    else if (p->ptrs.sp > p->ptrs.dp)
    {
        flow->ssn_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
}

static void init_roles_udp(Packet* p, Flow* flow)
{
    flow->ssn_state.direction = FROM_CLIENT;
    sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
    flow->client_port = ntohs(p->ptrs.udph->uh_sport);
    sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
    flow->server_port = ntohs(p->ptrs.udph->uh_dport);
}

static void init_roles_user(Packet* p, Flow* flow)
{
    if ( p->ptrs.decode_flags & DECODE_C2S )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = p->ptrs.sp;
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = p->ptrs.dp;
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = p->ptrs.dp;
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = p->ptrs.sp;
    }
}

static void init_roles(Packet* p, Flow* flow)
{
    switch ( flow->protocol )
    {
    case PktType::IP:
    case PktType::ICMP:
        init_roles_ip(p, flow);
        break;

    case PktType::TCP:
        init_roles_tcp(p, flow);
        break;

    case PktType::UDP:
        init_roles_udp(p, flow);
        break;

    case PktType::PDU:
    case PktType::FILE:
        init_roles_user(p, flow);
        break;

    default:
        break;
    }
}

unsigned FlowControl::process(Flow* flow, Packet* p)
{
    unsigned news = 0;

    p->flow = flow;

    if ( flow->flow_state )
        set_policies(snort_conf, flow->policy_id);

    else
    {
        init_roles(p, flow);
        Inspector* b = InspectorManager::get_binder();

        if ( b )
            b->eval(p);

        if ( !b || (flow->flow_state == Flow::INSPECT &&
            (!flow->ssn_client || !flow->session->setup(p))) )
            flow->set_state(Flow::ALLOW);

        ++news;
    }
    flow->set_direction(p);

    switch ( flow->flow_state )
    {
    case Flow::SETUP:
        flow->set_state(Flow::ALLOW);
        break;

    case Flow::INSPECT:
        assert(flow->ssn_client);
        assert(flow->ssn_server);
        flow->session->process(p);
        break;

    case Flow::ALLOW:
        if ( news )
            stream.stop_inspection(flow, p, SSN_DIR_BOTH, -1, 0);
        else
            DisableInspection(p);

        p->ptrs.decode_flags |= DECODE_PKT_TRUST;
        break;

    case Flow::BLOCK:
        if ( news )
            stream.drop_traffic(flow, SSN_DIR_BOTH);
        else
            Active::block_again();

        DisableInspection(p);
        break;

    case Flow::RESET:
        if ( news )
            stream.drop_traffic(flow, SSN_DIR_BOTH);
        else
            Active::reset_again();

        stream.blocked_session(flow, p);
        DisableInspection(p);
        break;
    }

    return news;
}

//-------------------------------------------------------------------------
// ip
//-------------------------------------------------------------------------

void FlowControl::init_ip(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    ip_cache = new FlowCache(fc, 5, 0);

    ip_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

    if ( !ip_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        ip_cache->push(ip_mem + i);

    get_ip = get_ssn;
}

void FlowControl::process_ip(Packet* p)
{
    if ( !ip_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = ip_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::IP);
        flow->session = get_ip(flow);
    }

    ip_count += process(flow, p);

    if ( flow->next && is_bidirectional(flow) )
        ip_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// icmp
//-------------------------------------------------------------------------

void FlowControl::init_icmp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    icmp_cache = new FlowCache(fc, 5, 0);

    icmp_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

    if ( !icmp_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        icmp_cache->push(icmp_mem + i);

    get_icmp = get_ssn;
}

void FlowControl::process_icmp(Packet* p)
{
    if ( !icmp_cache )
    {
        process_ip(p);
        return;
    }

    FlowKey key;
    set_key(&key, p);
    Flow* flow = icmp_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::ICMP);
        flow->session = get_icmp(flow);
    }

    icmp_count += process(flow, p);

    if ( flow->next && is_bidirectional(flow) )
        icmp_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// tcp
//-------------------------------------------------------------------------

void FlowControl::init_tcp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    tcp_cache = new FlowCache(fc, 5, 0);

    tcp_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

    if ( !tcp_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        tcp_cache->push(tcp_mem + i);

    get_tcp = get_ssn;
}

void FlowControl::process_tcp(Packet* p)
{
    if ( !tcp_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = tcp_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::TCP);
        flow->session = get_tcp(flow);
    }

    tcp_count += process(flow, p);

    if ( flow->next && is_bidirectional(flow) )
        tcp_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// udp
//-------------------------------------------------------------------------

void FlowControl::init_udp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    udp_cache = new FlowCache(fc, 5, 0);

    udp_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

    if ( !udp_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        udp_cache->push(udp_mem + i);

    get_udp = get_ssn;
}

void FlowControl::process_udp(Packet* p)
{
    if ( !udp_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = udp_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::UDP);
        flow->session = get_udp(flow);
    }

    udp_count += process(flow, p);

    if ( flow->next && is_bidirectional(flow) )
        udp_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// user
//-------------------------------------------------------------------------

void FlowControl::init_user(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    user_cache = new FlowCache(fc, 5, 0);

    user_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

    if ( !user_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        user_cache->push(user_mem + i);

    get_user = get_ssn;
}

void FlowControl::process_user(Packet* p)
{
    if ( !user_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = user_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::PDU);
        flow->session = get_user(flow);
    }

    user_count += process(flow, p);

    if ( flow->next && is_bidirectional(flow) )
        user_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// file
//-------------------------------------------------------------------------

void FlowControl::init_file(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    file_cache = new FlowCache(fc, 5, 0);

    file_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

    if ( !file_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        file_cache->push(file_mem + i);

    get_file = get_ssn;
}

void FlowControl::process_file(Packet* p)
{
    if ( !file_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = file_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::FILE);
        flow->session = get_file(flow);
    }

    file_count += process(flow, p);
}

//-------------------------------------------------------------------------
// expected
//-------------------------------------------------------------------------

void FlowControl::init_exp(uint32_t max)
{
    max >>= 9;

    if ( !max )
        max = 2;

    exp_cache = new ExpectCache(max);
}

char FlowControl::expected_flow(Flow* flow, Packet* p)
{
    char ignore = exp_cache->check(p, flow);

    if ( ignore )
    {
        DebugFormat(DEBUG_STREAM_STATE,
            "Stream: Ignoring packet from %d. Marking flow marked as ignore.\n",
            p->packet_flags & PKT_FROM_CLIENT ? "sender" : "responder");

        flow->ssn_state.ignore_direction = ignore;
        DisableInspection(p);
    }

    return ignore;
}

int FlowControl::add_expected(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    PktType protocol, char direction,
    FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, direction, fd);
}

int FlowControl::add_expected(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    PktType protocol, int16_t appId, FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, SSN_DIR_BOTH, fd, appId);
}

bool FlowControl::is_expected(Packet* p)
{
    return exp_cache->is_expected(p);
}

