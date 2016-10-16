//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow_control.h"

#include "detection/detection_engine.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "managers/inspector_manager.h"
#include "memory/memory_cap.h"
#include "packet_io/active.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "expect_cache.h"
#include "flow_cache.h"
#include "session.h"

FlowControl::FlowControl()
{ }

FlowControl::~FlowControl()
{
    DetectionEngine de;

    delete ip_cache;
    delete icmp_cache;
    delete tcp_cache;
    delete udp_cache;
    delete user_cache;
    delete file_cache;
    delete exp_cache;

    snort_free(ip_mem);
    snort_free(icmp_mem);
    snort_free(tcp_mem);
    snort_free(udp_mem);
    snort_free(user_mem);
    snort_free(file_mem);
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

PegCount FlowControl::get_flows(PktType type)
{
    switch ( type )
    {
    case PktType::IP:   return ip_count;
    case PktType::ICMP: return icmp_count;
    case PktType::TCP:  return tcp_count;
    case PktType::UDP:  return udp_count;
    case PktType::PDU:  return user_count;
    case PktType::FILE: return file_count;
    default:            return 0;
    }
}

PegCount FlowControl::get_total_prunes(PktType type) const
{
    auto cache = get_cache(type);
    return cache ? cache->get_total_prunes() : 0;
}

PegCount FlowControl::get_prunes(PktType type, PruneReason reason) const
{
    auto cache = get_cache(type);
    return cache ? cache->get_prunes(reason) : 0;
}

void FlowControl::clear_counts()
{
    ip_count = icmp_count = 0;
    tcp_count = udp_count = 0;
    user_count = file_count = 0;

    FlowCache* cache;

    if ( (cache = get_cache(PktType::IP)) )
        cache->reset_stats();

    if ( (cache = get_cache(PktType::ICMP)) )
        cache->reset_stats();

    if ( (cache = get_cache(PktType::TCP)) )
        cache->reset_stats();

    if ( (cache = get_cache(PktType::UDP)) )
        cache->reset_stats();

    if ( (cache = get_cache(PktType::PDU)) )
        cache->reset_stats();

    if ( (cache = get_cache(PktType::FILE)) )
        cache->reset_stats();
}

//-------------------------------------------------------------------------
// cache foo
//-------------------------------------------------------------------------

inline FlowCache* FlowControl::get_cache (PktType type)
{
    switch ( type )
    {
    case PktType::IP:   return ip_cache;
    case PktType::ICMP: return icmp_cache;
    case PktType::TCP:  return tcp_cache;
    case PktType::UDP:  return udp_cache;
    case PktType::PDU:  return user_cache;
    case PktType::FILE: return file_cache;
    default:            return nullptr;
    }
}

// FIXIT-L duplication of non-const method above
inline const FlowCache* FlowControl::get_cache (PktType type) const
{
    switch ( type )
    {
    case PktType::IP:   return ip_cache;
    case PktType::ICMP: return icmp_cache;
    case PktType::TCP:  return tcp_cache;
    case PktType::UDP:  return udp_cache;
    case PktType::PDU:  return user_cache;
    case PktType::FILE: return file_cache;
    default:            return nullptr;
    }
}

Flow* FlowControl::find_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache(key->pkt_type);

    if ( cache )
        return cache->find(key);

    return NULL;
}

Flow* FlowControl::new_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache(key->pkt_type);

    if ( !cache )
        return NULL;

    return cache->get(key);
}

// FIXIT-L cache* can be put in flow so that lookups by
// packet type are obviated for existing / initialized flows
void FlowControl::delete_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache(key->pkt_type);

    if ( !cache )
        return;

    Flow* flow = cache->find(key);

    if ( flow )
        cache->release(flow, PruneReason::HA);
}

void FlowControl::delete_flow(Flow* flow, PruneReason reason)
{
    FlowCache* cache = get_cache(flow->pkt_type);

    if ( cache )
        cache->release(flow, reason);
}

void FlowControl::purge_flows (PktType type)
{
    FlowCache* cache = get_cache(type);

    if ( cache )
        cache->purge();
}

// hole for memory manager/prune handler
bool FlowControl::prune_one(PruneReason reason, bool do_cleanup)
{
    auto cache = get_cache(last_pkt_type);
    return cache ? cache->prune_one(reason, do_cleanup) : false;
}

void FlowControl::timeout_flows(time_t cur_time)
{
    if ( !types.size() )
        return;

    Active::suspend();
    FlowCache* fc = get_cache(types[next]);

    if ( ++next >= types.size() )
        next = 0;

    if ( fc )
        fc->timeout(1, cur_time);

    Active::resume();
}

void FlowControl::preemptive_cleanup()
{
    DebugFormat(DEBUG_FLOW, "doing preemptive cleanup for packet of type %u",
            (unsigned) last_pkt_type);

    // FIXIT-H is there a possibility of this looping forever?
    while ( memory::MemoryCap::over_threshold() )
    {
        if ( !prune_one(PruneReason::PREEMPTIVE, true) )
            break;
    }
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
    PktType type = p->type();
    IpProtocol ip_proto = p->get_ip_proto_next();

    if ( p->proto_bits & PROTO_BIT__VLAN )
        vlanId = layer::get_vlan_layer(p)->vid();
    else
        vlanId = 0;

    if ( p->proto_bits & PROTO_BIT__MPLS )
        mplsId = p->ptrs.mplsHdr.label;
    else
        mplsId = 0;

    addressSpaceId = p->pkth->address_space_id;

    if ( (p->ptrs.decode_flags & DECODE_FRAG) )
    {
        key->init(type, ip_proto, ip_api.get_src(), ip_api.get_dst(), ip_api.id(),
            vlanId, mplsId, addressSpaceId);
    }
    else if ( type == PktType::ICMP )
    {
        key->init(type, ip_proto, ip_api.get_src(), p->ptrs.icmph->type, ip_api.get_dst(), 0,
            vlanId, mplsId, addressSpaceId);
    }
    else
    {
        key->init(type, ip_proto, ip_api.get_src(), p->ptrs.sp, ip_api.get_dst(), p->ptrs.dp,
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
    flow->client_ip.set(*p->ptrs.ip_api.get_src());
    flow->server_ip.set(*p->ptrs.ip_api.get_dst());
}

static void init_roles_tcp(Packet* p, Flow* flow)
{
    if ( p->ptrs.tcph->is_syn_only() )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        flow->client_ip.set(*p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        flow->server_ip.set(*p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else if ( p->ptrs.tcph->is_syn_ack() )
    {
        flow->ssn_state.direction = FROM_SERVER;
        flow->client_ip.set(*p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        flow->server_ip.set(*p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
    else if (p->ptrs.sp > p->ptrs.dp)
    {
        flow->ssn_state.direction = FROM_CLIENT;
        flow->client_ip.set(*p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        flow->server_ip.set(*p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        flow->client_ip.set(*p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        flow->server_ip.set(*p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
}

static void init_roles_udp(Packet* p, Flow* flow)
{
    flow->ssn_state.direction = FROM_CLIENT;
    flow->client_ip.set(*p->ptrs.ip_api.get_src());
    flow->client_port = ntohs(p->ptrs.udph->uh_sport);
    flow->server_ip.set(*p->ptrs.ip_api.get_dst());
    flow->server_port = ntohs(p->ptrs.udph->uh_dport);
}

static void init_roles_user(Packet* p, Flow* flow)
{
    if ( p->ptrs.decode_flags & DECODE_C2S )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        flow->client_ip.set(*p->ptrs.ip_api.get_src());
        flow->client_port = p->ptrs.sp;
        flow->server_ip.set(*p->ptrs.ip_api.get_dst());
        flow->server_port = p->ptrs.dp;
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        flow->client_ip.set(*p->ptrs.ip_api.get_dst());
        flow->client_port = p->ptrs.dp;
        flow->server_ip.set(*p->ptrs.ip_api.get_src());
        flow->server_port = p->ptrs.sp;
    }
}

static void init_roles(Packet* p, Flow* flow)
{
    switch ( flow->pkt_type )
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

    assert ( flow );
    flow->previous_ssn_state = flow->ssn_state;

    p->flow = flow;
    p->disable_inspect = flow->is_inspection_disabled();

    last_pkt_type = p->type();
    preemptive_cleanup();
    flow->set_direction(p);
    flow->session->precheck(p);

    if ( flow->flow_state != Flow::FlowState::SETUP )
        set_policies(snort_conf, flow->policy_id);

    else
    {
        init_roles(p, flow);
        Inspector* b = InspectorManager::get_binder();

        if ( b )
            b->eval(p);

        if ( !b || (flow->flow_state == Flow::FlowState::INSPECT &&
            (!flow->ssn_client || !flow->session->setup(p))) )
            flow->set_state(Flow::FlowState::ALLOW);

        ++news;
    }

    flow->set_direction(p);

    // This requires the packet direction to be set
    if ( p->proto_bits & PROTO_BIT__MPLS )
        flow->set_mpls_layer_per_dir(p);

    if ( p->type() == PktType::PDU )  // FIXIT-H cooked or PDU?
        DetectionEngine::onload(flow);

    switch ( flow->flow_state )
    {
    case Flow::FlowState::SETUP:
        flow->set_state(Flow::FlowState::ALLOW);
        break;

    case Flow::FlowState::INSPECT:
        assert(flow->ssn_client);
        assert(flow->ssn_server);
        flow->session->process(p);
        break;

    case Flow::FlowState::ALLOW:
        if ( news )
            Stream::stop_inspection(flow, p, SSN_DIR_BOTH, -1, 0);
        else
            DetectionEngine::disable_all(p);

        p->ptrs.decode_flags |= DECODE_PKT_TRUST;
        break;

    case Flow::FlowState::BLOCK:
        if ( news )
            Stream::drop_traffic(flow, SSN_DIR_BOTH);
        else
            Active::block_again();

        DetectionEngine::disable_all(p);
        break;

    case Flow::FlowState::RESET:
        if ( news )
            Stream::drop_traffic(flow, SSN_DIR_BOTH);
        else
            Active::reset_again();

        Stream::blocked_flow(flow, p);
        DetectionEngine::disable_all(p);
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

    ip_cache = new FlowCache(fc);
    ip_mem = (Flow*)snort_calloc(fc.max_sessions, sizeof(Flow));

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        ip_cache->push(ip_mem + i);

    get_ip = get_ssn;
    types.push_back(PktType::IP);
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

    icmp_cache = new FlowCache(fc);
    icmp_mem = (Flow*)snort_calloc(fc.max_sessions, sizeof(Flow));

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        icmp_cache->push(icmp_mem + i);

    get_icmp = get_ssn;
    types.push_back(PktType::ICMP);
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

    tcp_cache = new FlowCache(fc);
    tcp_mem = (Flow*)snort_calloc(fc.max_sessions, sizeof(Flow));

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        tcp_cache->push(tcp_mem + i);

    get_tcp = get_ssn;
    types.push_back(PktType::TCP);
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

    udp_cache = new FlowCache(fc);
    udp_mem = (Flow*)snort_calloc(fc.max_sessions, sizeof(Flow));

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        udp_cache->push(udp_mem + i);

    get_udp = get_ssn;
    types.push_back(PktType::UDP);
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

    user_cache = new FlowCache(fc);
    user_mem = (Flow*)snort_calloc(fc.max_sessions, sizeof(Flow));

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        user_cache->push(user_mem + i);

    get_user = get_ssn;
    types.push_back(PktType::PDU);
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

    file_cache = new FlowCache(fc);
    file_mem = (Flow*)snort_calloc(fc.max_sessions, sizeof(Flow));

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        file_cache->push(file_mem + i);

    get_file = get_ssn;
    types.push_back(PktType::FILE);
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

bool FlowControl::expected_flow(Flow* flow, Packet* p)
{
    bool ignore = exp_cache->check(p, flow);

    if ( ignore )
    {
        DebugFormat(DEBUG_STREAM_STATE,
            "Stream: Ignoring packet from %s. Marking flow marked as ignore.\n",
            (p->packet_flags & PKT_FROM_CLIENT) ? "sender" : "responder");

        flow->ssn_state.ignore_direction = ignore;
        DetectionEngine::disable_all(p);
    }

    return ignore;
}

int FlowControl::add_expected(
    const Packet* ctrlPkt, PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    char direction, FlowData* fd)
{
    return exp_cache->add_flow(
        ctrlPkt, type, ip_proto, srcIP, srcPort, dstIP, dstPort,
        direction, fd);
}

int FlowControl::add_expected(
    const Packet* ctrlPkt, PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort,
    const SfIp *dstIP, uint16_t dstPort,
    int16_t appId, FlowData* fd)
{
    return exp_cache->add_flow(
        ctrlPkt, type, ip_proto, srcIP, srcPort, dstIP, dstPort,
        SSN_DIR_BOTH, fd, appId);
}

bool FlowControl::is_expected(Packet* p)
{
    return exp_cache->is_expected(p);
}

