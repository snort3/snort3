//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

#include <daq_common.h>

#include "flow_control.h"

#include "detection/detection_engine.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "packet_io/active.h"
#include "packet_tracer/packet_tracer.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "expect_cache.h"
#include "flow_cache.h"
#include "ha.h"
#include "session.h"

using namespace snort;

FlowControl::FlowControl(const FlowCacheConfig& fc)
{
    cache = new FlowCache(fc);
}

FlowControl::~FlowControl()
{
    DetectionEngine de;

    delete cache;
    snort_free(mem);
    delete exp_cache;
}

//-------------------------------------------------------------------------
// count foo
//-------------------------------------------------------------------------

PegCount FlowControl::get_total_prunes() const
{ return cache->get_total_prunes(); }

PegCount FlowControl::get_prunes(PruneReason reason) const
{ return cache->get_prunes(reason); }

PegCount FlowControl::get_total_deletes() const
{ return cache->get_total_deletes(); }

PegCount FlowControl::get_deletes(FlowDeleteState state) const
{ return cache->get_deletes(state); }

void FlowControl::clear_counts()
{
    cache->reset_stats();
    num_flows = 0;
}

//-------------------------------------------------------------------------
// cache foo
//-------------------------------------------------------------------------

void FlowControl::set_flow_cache_config(const FlowCacheConfig& cfg)
{ cache->set_flow_cache_config(cfg); }

const FlowCacheConfig& FlowControl::get_flow_cache_config() const
{ return cache->get_flow_cache_config(); }

unsigned FlowControl::get_flows_allocated() const
{ return cache->get_flows_allocated(); }

Flow* FlowControl::find_flow(const FlowKey* key)
{ return cache->find(key); }

Flow* FlowControl::new_flow(const FlowKey* key)
{ return cache->allocate(key); }

void FlowControl::release_flow(const FlowKey* key)
{
    if ( auto flow = cache->find(key) )
        cache->release(flow, PruneReason::HA);
}

void FlowControl::release_flow(Flow* flow, PruneReason reason)
{ cache->release(flow, reason); }

void FlowControl::purge_flows ()
{ cache->purge(); }

unsigned FlowControl::delete_flows(unsigned num_to_delete)
{ return cache->delete_flows(num_to_delete); }

// hole for memory manager/prune handler
bool FlowControl::prune_one(PruneReason reason, bool do_cleanup)
{ return cache->prune_one(reason, do_cleanup); }

void FlowControl::timeout_flows(time_t cur_time)
{
    cache->timeout(1, cur_time);
}

Flow* FlowControl::stale_flow_cleanup(FlowCache* cache, Flow* flow, Packet* p)
{
    if ( p->pkth->flags & DAQ_PKT_FLAG_NEW_FLOW )
    {
        if (PacketTracer::is_active())
            PacketTracer::log("Session: deleting snort session, reason: stale and not cleaned \n");

        ActiveSuspendContext act_susp(Active::ASP_TIMEOUT);

        {
            PacketTracerSuspend pt_susp;

            cache->release(flow, PruneReason::STALE);
            flow = nullptr;
        }
    }

    return flow;
}

//-------------------------------------------------------------------------
// packet foo
//-------------------------------------------------------------------------

void FlowControl::set_key(FlowKey* key, Packet* p)
{
    const ip::IpApi& ip_api = p->ptrs.ip_api;
    uint32_t mplsId;
    uint16_t vlanId;
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

    if ( (p->ptrs.decode_flags & DECODE_FRAG) )
    {
        key->init(p->context->conf, type, ip_proto, ip_api.get_src(),
            ip_api.get_dst(), ip_api.id(), vlanId, mplsId, *p->pkth);
    }
    else if ( type == PktType::ICMP )
    {
        key->init(p->context->conf, type, ip_proto, ip_api.get_src(), p->ptrs.icmph->type,
            ip_api.get_dst(), 0, vlanId, mplsId, *p->pkth);
    }
    else
    {
        key->init(p->context->conf, type, ip_proto, ip_api.get_src(), p->ptrs.sp,
            ip_api.get_dst(), p->ptrs.dp, vlanId, mplsId, *p->pkth);
    }
}

static bool is_bidirectional(const Flow* flow)
{
    constexpr unsigned bidir = SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER;
    return (flow->ssn_state.session_flags & bidir) == bidir;
}

static void init_roles_ip(const Packet* p, Flow* flow)
{
    flow->ssn_state.direction = FROM_CLIENT;
    flow->client_ip = *p->ptrs.ip_api.get_src();
    flow->server_ip = *p->ptrs.ip_api.get_dst();
}

static bool init_roles_tcp(const Packet* p, Flow* flow)
{
    bool swapped;
    if ( p->ptrs.tcph->is_syn_only() )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        flow->client_ip = *p->ptrs.ip_api.get_src();
        flow->client_port = p->ptrs.sp;
        flow->server_ip = *p->ptrs.ip_api.get_dst();
        flow->server_port = p->ptrs.dp;
        swapped = false;
    }
    else if ( p->ptrs.tcph->is_syn_ack() )
    {
        flow->ssn_state.direction = FROM_SERVER;
        flow->client_ip = *p->ptrs.ip_api.get_dst();
        flow->client_port = p->ptrs.dp;
        flow->server_ip = *p->ptrs.ip_api.get_src();
        flow->server_port = p->ptrs.sp;
        swapped = true;
    }
    else if (p->ptrs.sp > p->ptrs.dp)
    {
        flow->ssn_state.direction = FROM_CLIENT;
        flow->client_ip = *p->ptrs.ip_api.get_src();
        flow->client_port = p->ptrs.sp;
        flow->server_ip = *p->ptrs.ip_api.get_dst();
        flow->server_port = p->ptrs.dp;
        swapped = false;
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        flow->client_ip = *p->ptrs.ip_api.get_dst();
        flow->client_port = p->ptrs.dp;
        flow->server_ip = *p->ptrs.ip_api.get_src();
        flow->server_port = p->ptrs.sp;
        swapped = true;
    }
    return swapped;
}

static void init_roles_udp(const Packet* p, Flow* flow)
{
    flow->ssn_state.direction = FROM_CLIENT;
    flow->client_ip = *p->ptrs.ip_api.get_src();
    flow->client_port = p->ptrs.sp;
    flow->server_ip = *p->ptrs.ip_api.get_dst();
    flow->server_port = p->ptrs.dp;
}

static bool init_roles_user(const Packet* p, Flow* flow)
{
    bool swapped;
    if ( p->ptrs.decode_flags & DECODE_C2S )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        flow->client_ip = *p->ptrs.ip_api.get_src();
        flow->client_port = p->ptrs.sp;
        flow->server_ip = *p->ptrs.ip_api.get_dst();
        flow->server_port = p->ptrs.dp;
        swapped = false;
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        flow->client_ip = *p->ptrs.ip_api.get_dst();
        flow->client_port = p->ptrs.dp;
        flow->server_ip = *p->ptrs.ip_api.get_src();
        flow->server_port = p->ptrs.sp;
        swapped = true;
    }
    return swapped;
}

// FIXIT-L init_roles should take const Packet*
static void init_roles(Packet* p, Flow* flow)
{
    bool swapped = false;
    switch ( flow->pkt_type )
    {
        case PktType::IP:
        case PktType::ICMP:
            init_roles_ip(p, flow);
            break;

        case PktType::TCP:
            swapped = init_roles_tcp(p, flow);
            break;

        case PktType::UDP:
            init_roles_udp(p, flow);
            break;

        case PktType::FILE:
        case PktType::USER:
            swapped = init_roles_user(p, flow);
            break;

        default:
            break;
    }

    if (swapped)
    {
        flow->client_intf = p->pkth->egress_index;
        flow->server_intf = p->pkth->ingress_index;
        flow->client_group = p->pkth->egress_group;
        flow->server_group = p->pkth->ingress_group;
    }
    else
    {
        flow->client_intf = p->pkth->ingress_index;
        flow->server_intf = p->pkth->egress_index;
        flow->client_group = p->pkth->ingress_group;
        flow->server_group = p->pkth->egress_group;
    }

    flow->tenant = p->get_flow_geneve_vni();

    flow->flags.app_direction_swapped = false;
    if ( flow->ssn_state.direction == FROM_CLIENT )
        p->packet_flags |= PKT_FROM_CLIENT;
    else
        p->packet_flags |= PKT_FROM_SERVER;
}

//-------------------------------------------------------------------------
// proto
//-------------------------------------------------------------------------

void FlowControl::init_proto(PktType type, InspectSsnFunc get_ssn)
{
    assert(get_ssn);

    get_proto_session[to_utype(type)] = get_ssn;
}

// FIXIT-P apply more filtering logic here, eg require_3whs
// delegate to stream inspectors but that requires binding
// can't use session because goal is to avoid instantiation
static bool want_flow(PktType type, Packet* p)
{
    if ( type != PktType::TCP )
        return true;

    if ( p->is_retry() )
    {
        // Do not start a new flow from a retry packet.
        p->active->drop_packet(p);
        p->disable_inspect = true;
        return false;
    }

    if ( p->ptrs.tcph->is_rst() )
        // guessing direction based on ports is misleading
        return false;

    if ( !p->ptrs.tcph->is_syn_only() or p->context->conf->track_on_syn() )
        return true;

    const unsigned DECODE_TCP_HS = DECODE_TCP_MSS | DECODE_TCP_TS | DECODE_TCP_WS;

    if ( (p->ptrs.decode_flags & DECODE_TCP_HS) or p->dsize )
        return true;

    p->packet_flags |= PKT_FROM_CLIENT;
    return false;
}

bool FlowControl::process(PktType type, Packet* p, bool* new_flow)
{
    if ( !get_proto_session[to_utype(type)] )
        return false;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = cache->find(&key);

    if (flow)
        flow = stale_flow_cleanup(cache, flow, p);

    if ( !flow )
    {
        flow = HighAvailabilityManager::import(*p, key);

        if ( !flow )
        {
            if ( !want_flow(type, p) )
                return true;

            flow = cache->allocate(&key);

            if ( !flow )
                return true;

            if ( new_flow )
                *new_flow = true;
        }
    }

    if ( !flow->session )
    {
        flow->init(type);
        flow->session = get_proto_session[to_utype(type)](flow);
    }

    num_flows += process(flow, p);

    // FIXIT-M refactor to unlink_uni immediately after session
    // is processed by inspector manager (all flows)
    if ( is_bidirectional(flow) )
        cache->unlink_uni(flow);

    return true;
}

unsigned FlowControl::process(Flow* flow, Packet* p)
{
    unsigned news = 0;

    flow->previous_ssn_state = flow->ssn_state;

    p->flow = flow;
    p->disable_inspect = flow->is_inspection_disabled();

    last_pkt_type = p->type();

    // If this code is executed on a flow in SETUP state, it will result in a packet from both
    // client and server on packets from 0.0.0.0 or ::
    if ( flow->flow_state != Flow::FlowState::SETUP )
    {
        flow->set_direction(p);

        // This call can reset the flow state to SETUP in lazy flow timeout cases
        if ( flow->flow_state != Flow::FlowState::ALLOW )
            flow->session->precheck(p);
    }

    if ( flow->flow_state != Flow::FlowState::SETUP )
    {
        const SnortConfig* sc = SnortConfig::get_conf();
        set_inspection_policy(sc, flow->inspection_policy_id);
        set_ips_policy(sc, flow->ips_policy_id);
        p->filtering_state = flow->filtering_state;
    }

    else
    {
        if (PacketTracer::is_active())
            PacketTracer::log("Session: new snort session\n");

        init_roles(p, flow);

        // process expected flows
        check_expected_flow(flow, p);

        flow->set_client_initiate(p);
        DataBus::publish(FLOW_STATE_SETUP_EVENT, p);

        if ( flow->flow_state == Flow::FlowState::SETUP ||
            (flow->flow_state == Flow::FlowState::INSPECT &&
             (!flow->ssn_client || !flow->session->setup(p))) )
            flow->set_state(Flow::FlowState::ALLOW);

        ++news;
        flow->flowstats.start_time = p->pkth->ts;
    }

    // This requires the packet direction to be set
    if ( p->proto_bits & PROTO_BIT__MPLS )
        flow->set_mpls_layer_per_dir(p);

    switch ( flow->flow_state )
    {
    case Flow::FlowState::SETUP:
        flow->set_state(Flow::FlowState::ALLOW);
        break;

    case Flow::FlowState::INSPECT:
        assert(flow->ssn_client);
        assert(flow->ssn_server);
        break;

    case Flow::FlowState::ALLOW:
        if ( news )
            Stream::stop_inspection(flow, p, SSN_DIR_BOTH, -1, 0);
        else
            DetectionEngine::disable_all(p);
        break;

    case Flow::FlowState::BLOCK:
        if ( news )
            Stream::drop_traffic(p, SSN_DIR_BOTH);
        else
            p->active->block_again();

        p->active->set_drop_reason("session");
        DetectionEngine::disable_all(p);
        if ( PacketTracer::is_active() )
            PacketTracer::log("Session: session has been blocked, drop\n");
        break;

    case Flow::FlowState::RESET:
        if ( news )
            Stream::drop_traffic(p, SSN_DIR_BOTH);
        else
            p->active->reset_again();

        Stream::blocked_flow(p);
        p->active->set_drop_reason("session");
        DetectionEngine::disable_all(p);
        if ( PacketTracer::is_active() )
            PacketTracer::log("Session: session has been reset\n");
        break;
    }

    update_stats(flow, p);
    return news;
}

void FlowControl::update_stats(Flow* flow, Packet* p)
{
    if (p->is_from_client())
    {
        flow->flowstats.client_pkts++;
        flow->flowstats.client_bytes += p->pktlen;
    }
    else
    {
        flow->flowstats.server_pkts++;
        flow->flowstats.server_bytes += p->pktlen;
    }
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

void FlowControl::check_expected_flow(Flow* flow, Packet* p)
{
    bool ignore = exp_cache->check(p, flow);

    if ( ignore )
    {
        flow->ssn_state.ignore_direction = ignore;
        DetectionEngine::disable_all(p);
    }
}

int FlowControl::add_expected_ignore( const Packet* ctrlPkt, PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort, const SfIp *dstIP, uint16_t dstPort, char direction,
    FlowData* fd)
{
    return exp_cache->add_flow( ctrlPkt, type, ip_proto, srcIP, srcPort, dstIP, dstPort, direction,
        fd);
}

int FlowControl::add_expected( const Packet* ctrlPkt, PktType type, IpProtocol ip_proto,
    const SfIp *srcIP, uint16_t srcPort, const SfIp *dstIP, uint16_t dstPort,
    SnortProtocolId snort_protocol_id, FlowData* fd, bool swap_app_direction, bool expect_multi,
    bool bidirectional)
{
    return exp_cache->add_flow( ctrlPkt, type, ip_proto, srcIP, srcPort, dstIP, dstPort,
        SSN_DIR_BOTH, fd, snort_protocol_id, swap_app_direction, expect_multi, bidirectional);
}

bool FlowControl::is_expected(Packet* p)
{
    return exp_cache->is_expected(p);
}

