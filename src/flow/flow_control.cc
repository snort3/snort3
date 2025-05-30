//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <sys/time.h>

#include <daq_common.h>

#include "flow_control.h"

#include "detection/detection_engine.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "pub_sub/packet_events.h"
#include "stream/stream.h"
#include "utils/stats.h"
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

PegCount FlowControl::get_proto_prune_count(PruneReason reason, PktType type) const
{ return cache->get_proto_prune_count(reason,type); }

PegCount FlowControl::get_total_deletes() const
{ return cache->get_total_deletes(); }

PegCount FlowControl::get_deletes(FlowDeleteState state) const
{ return cache->get_deletes(state); }

void FlowControl::clear_counts()
{
    cache->reset_stats();
    num_flows = 0;
}

PegCount FlowControl::get_uni_flows() const
{ return cache->uni_flows_size(); }

PegCount FlowControl::get_uni_ip_flows() const
{ return cache->uni_ip_flows_size(); }

PegCount FlowControl::get_num_flows() const
{ return cache->flows_size(); }


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

bool FlowControl::move_to_allowlist(Flow* f)
{
    // Preserve the flow only if it is a TCP or UDP flow,
    // as only these flow types contain appid-related info needed at the EOF event.
    if ( f->key->pkt_type != PktType::TCP and f->key->pkt_type != PktType::UDP )
        return false;
    return cache->move_to_allowlist(f);
}

PegCount FlowControl::get_allowlist_flow_count() const
{ return cache->get_lru_flow_count(allowlist_lru_index); }

PegCount FlowControl::get_excess_to_allowlist_count() const
{ return cache->get_excess_to_allowlist_count(); }

void FlowControl::release_flow(Flow* flow, PruneReason reason)
{ cache->release(flow, reason); }

void FlowControl::purge_flows ()
{ cache->purge(); }

unsigned FlowControl::delete_flows(unsigned num_to_delete)
{ return cache->delete_flows(num_to_delete); }

// hole for memory manager/prune handler
bool FlowControl::prune_one(PruneReason reason, bool do_cleanup)
{ return cache->prune_one(reason, do_cleanup); }

unsigned FlowControl::prune_multiple(PruneReason reason, bool do_cleanup)
{ return cache->prune_multiple(reason, do_cleanup); }

bool FlowControl::dump_flows(std::fstream& stream, unsigned count, const FilterFlowCriteria& ffc, bool first, uint8_t code) const
{ return cache->dump_flows(stream, count, ffc, first, code); }

bool FlowControl::dump_flows_summary(FlowsSummary& flows_summary, const FilterFlowCriteria &ffc) const
{ return cache->dump_flows_summary(flows_summary, ffc); }

void FlowControl::timeout_flows(unsigned max, time_t cur_time)
{
    cache->timeout(max, cur_time);
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

            if ( cache->release(flow, PruneReason::STALE) )
                flow = nullptr;
        }
    }

    return flow;
}

//-------------------------------------------------------------------------
// packet foo
//-------------------------------------------------------------------------

bool FlowControl::set_key(FlowKey* key, Packet* p)
{
    const ip::IpApi& ip_api = p->ptrs.ip_api;
    uint32_t mplsId;
    uint16_t vlanId;
    PktType type = p->type();
    IpProtocol ip_proto = p->get_ip_proto_next();
    bool reversed;

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
        reversed = key->init(p->context->conf, type, ip_proto, ip_api.get_src(),
            ip_api.get_dst(), ip_api.id(), vlanId, mplsId, *p->pkth);
    }
    else if ( type == PktType::ICMP )
    {
        reversed = key->init(p->context->conf, type, ip_proto, ip_api.get_src(), p->ptrs.icmph->type,
            ip_api.get_dst(), 0, vlanId, mplsId, *p->pkth);
    }
    else
    {
        reversed = key->init(p->context->conf, type, ip_proto, ip_api.get_src(), p->ptrs.sp,
            ip_api.get_dst(), p->ptrs.dp, vlanId, mplsId, *p->pkth);
    }
    return reversed;
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

    if ( p->ptrs.tcph->is_syn_only() )
    {
        if ( Stream::require_3whs() )
            return true;

        if ( p->context->conf->track_on_syn() )
            return true;

        if ( p->ptrs.decode_flags & (DECODE_TCP_MSS | DECODE_TCP_TS | DECODE_TCP_WS) )
            return true;
    }

    if ( p->ptrs.tcph->is_syn_ack() or p->dsize )
        return Stream::midstream_allowed(p, true);

    p->packet_flags |= PKT_FROM_CLIENT;
    return false;
}

static void log_stale_packet(snort::Packet *p, snort::Flow *flow, bool drop_packet)
{
    char ts_flow[TIMEBUF_SIZE];
    char ts_pkt[TIMEBUF_SIZE];
    ts_print((const struct timeval *)&p->pkth->ts, ts_pkt);
    ts_print((const struct timeval *)&flow->prev_packet_time, ts_flow);

    if ( drop_packet )
        PacketTracer::log("Flow: Dropping stale packet. current packet ts: %s < previous packet ts: %s.\n",
                          ts_pkt, ts_flow);
    else
        PacketTracer::log("Flow: Detected stale packet, dropping disabled. current packet ts: %s < previous packet ts: %s.\n",
                          ts_pkt, ts_flow);
}

static inline bool is_packet_stale(const Flow* flow, const Packet* p)
{
    return timercmp(&flow->prev_packet_time, &p->pkth->ts, >);
}

static void drop_stale_packet(snort::Packet *p, snort::Flow *flow)
{
    // This is a stale packet, ignore it.
    p->active->set_drop_reason("snort");
    p->active->drop_packet(p);
    p->disable_inspect = true;
    if ( PacketTracer::is_active() )
        log_stale_packet(p, flow, true);
}

bool FlowControl::process(PktType type, Packet* p, bool* new_flow)
{
    if ( !get_proto_session[to_utype(type)] )
        return false;

    FlowKey key;
    bool reversed = set_key(&key, p);
    Flow* flow = cache->find(&key);

    if ( flow )
    {
        if ( !p->is_retry() and is_packet_stale(flow, p) )
        {
            flow->session->count_stale_packet();

            if ( p->context->conf->drop_stale_packets() )
            {
                drop_stale_packet(p, flow);
                return true;
            }
            else
            {
                if ( PacketTracer::is_active() )
                    log_stale_packet(p, flow, false);
            }
        }
        
        flow = stale_flow_cleanup(cache, flow, p);
    }

    bool new_ha_flow = false;
    if ( !flow )
    {
        flow = HighAvailabilityManager::import(*p, key);

        if ( flow )
            new_ha_flow = true;
        else
        {
            if ( !want_flow(type, p) )
                return true;

            flow = cache->allocate(&key);

            if ( !flow )
                return true;

            if ( p->is_tcp() and p->ptrs.tcph->is_syn_ack() )
                flow->flags.key_is_reversed = !reversed;
            else
                flow->flags.key_is_reversed = reversed;

            if ( new_flow )
                *new_flow = true;
        }
    }

    if ( !flow->session )
    {
        flow->init(type);
        flow->session = get_proto_session[to_utype(type)](flow);
    }

    num_flows += process(flow, p, new_ha_flow);

    // FIXIT-M refactor to unlink_uni immediately after session
    // is processed by inspector manager (all flows)
    if ( is_bidirectional(flow) )
        cache->unlink_uni(flow);

    return true;
}

static inline void restart_inspection(Flow* flow, Packet* p)
{
    p->disable_inspect = false;
    flow->flags.disable_inspect = false;
    flow->flow_state = Flow::FlowState::SETUP;
    flow->last_verdict = MAX_DAQ_VERDICT;
}

unsigned FlowControl::process(Flow* flow, Packet* p, bool new_ha_flow)
{
    unsigned news = 0;

    flow->previous_ssn_state = flow->ssn_state;
    flow->prev_packet_time = p->pkth->ts;

    p->flow = flow;
    p->disable_inspect = flow->is_inspection_disabled();

    if ( p->disable_inspect and p->type() == PktType::ICMP
         and flow->reload_id and SnortConfig::get_thread_reload_id() != flow->reload_id )
        restart_inspection(flow, p);

    last_pkt_type = p->type();

    // If this code is executed on a flow in SETUP state, it will result in a packet from both
    // client and server on packets from 0.0.0.0 or ::
    if ( flow->flow_state != Flow::FlowState::SETUP )
    {
        flow->set_direction(p);

        // This call can reset the flow state to SETUP in lazy flow timeout cases
        if ( flow->flow_state == Flow::FlowState::INSPECT and !flow->session->precheck(p) )
        {
            // flow expired, must recheck eligibility
            if ( !want_flow(flow->pkt_type, p) )
            {
                flow->session_state |= STREAM_STATE_CLOSED;
                return 0;  // flow will be deleted
            }
            // flow will restart using existing service
            // FIXIT-M reuse direction or clear service and use wizard
        }
    }

    if ( flow->flow_state != Flow::FlowState::SETUP )
    {
        if ( new_ha_flow )
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_STATE_SETUP, p);
        unsigned reload_id = SnortConfig::get_thread_reload_id();
        if ( flow->reload_id != reload_id )
            flow->network_policy_id = get_network_policy()->policy_id;
        else
        {
            set_inspection_policy(flow->inspection_policy_id);
            set_ips_policy(p->context->conf, flow->ips_policy_id);
        }
        p->filtering_state = flow->filtering_state;
        update_stats(flow, p);
        if ( p->is_retry() )
        {
            RetryPacketEvent retry_event(p);
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::RETRY_PACKET, retry_event);
            flow->flags.retry_queued = false;
        }
        else if ( flow->flags.retry_queued and ( !p->is_cooked() or p->is_defrag() ) )
        {
            RetryPacketEvent retry_event(p);
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::RETRY_PACKET, retry_event);
            if ( !retry_event.is_still_pending() )
                flow->flags.retry_queued = false;
        }
    }
    else
    {
        flow->network_policy_id = get_network_policy()->policy_id;
        if ( PacketTracer::is_active() )
            PacketTracer::log("Session: new snort session\n");

        init_roles(p, flow);

        // process expected flows
        check_expected_flow(flow, p);

        update_stats(flow, p);

        flow->set_client_initiate(p);
        DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_STATE_SETUP, p);

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
        flow->ssn_state.ignore_direction = SSN_DIR_BOTH;
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
    bool bidirectional, bool expect_persist)
{
    return exp_cache->add_flow( ctrlPkt, type, ip_proto, srcIP, srcPort, dstIP, dstPort,
        SSN_DIR_BOTH, fd, snort_protocol_id, swap_app_direction, expect_multi, bidirectional, expect_persist);
}

