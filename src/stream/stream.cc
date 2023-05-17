//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "stream.h"

#include <cassert>
#include <mutex>

#include "detection/detection_engine.h"
#include "flow/flow_cache.h"
#include "flow/flow_control.h"
#include "flow/flow_key.h"
#include "flow/ha.h"
#include "flow/prune_stats.h"
#include "framework/data_bus.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "network_inspectors/packet_tracer/packet_tracer.h"
#include "packet_io/active.h"
#include "protocols/vlan.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/base/stream_module.h"
#include "target_based/host_attributes.h"
#include "target_based/snort_protocols.h"
#include "trace/trace_api.h"
#include "utils/util.h"

#include "tcp/tcp_session.h"
#include "tcp/tcp_stream_session.h"
#include "tcp/tcp_stream_tracker.h"

using namespace snort;

#define IDLE_PRUNE_MAX 400

// this should not be publicly accessible
extern THREAD_LOCAL class FlowControl* flow_con;

struct StreamImpl
{
public:
    uint32_t xtradata_func_count = 0;
    LogFunction xtradata_map[MAX_LOG_FN];
    LogExtraData extra_data_log = nullptr;
    void* extra_data_config = nullptr;
};

static StreamImpl stream;
static std::mutex stream_xtra_mutex;

//-------------------------------------------------------------------------
// session foo
//-------------------------------------------------------------------------

Flow* Stream::get_flow(const FlowKey* key)
{ return flow_con->find_flow(key); }

Flow* Stream::new_flow(const FlowKey* key)
{ return flow_con->new_flow(key); }

void Stream::delete_flow(const FlowKey* key)
{ flow_con->release_flow(key); }

void Stream::delete_flow(Flow* flow)
{
    flow_con->release_flow(flow, PruneReason::NONE);
}

//-------------------------------------------------------------------------
// key foo
//-------------------------------------------------------------------------

Flow* Stream::get_flow(
    PktType type, IpProtocol proto,
    const SfIp* srcIP, uint16_t srcPort,
    const SfIp* dstIP, uint16_t dstPort,
    uint16_t vlan, uint32_t mplsId, uint32_t addressSpaceId,
    int16_t ingress_group, int16_t egress_group)
{
    FlowKey key;
    const SnortConfig* sc = SnortConfig::get_conf();

    key.init(sc, type, proto, srcIP, srcPort, dstIP, dstPort, vlan, mplsId,
        addressSpaceId, ingress_group, egress_group);
    return get_flow(&key);
}

Flow* Stream::get_flow(
    PktType type, IpProtocol proto,
    const SfIp* srcIP, uint16_t srcPort,
    const SfIp* dstIP, uint16_t dstPort,
    uint16_t vlan, uint32_t mplsId, const DAQ_PktHdr_t& pkth)
{
    FlowKey key;
    const SnortConfig* sc = SnortConfig::get_conf();

    key.init(sc, type, proto, srcIP, srcPort, dstIP, dstPort, vlan, mplsId,
        pkth);
    return get_flow(&key);
}

void Stream::populate_flow_key(const Packet* p, FlowKey* key)
{
    if (!key || !p)
        return;

    key->init(
        SnortConfig::get_conf(),
        p->type(), p->get_ip_proto_next(),
        p->ptrs.ip_api.get_src(), p->ptrs.sp,
        p->ptrs.ip_api.get_dst(), p->ptrs.dp,
        // if the vlan protocol bit is defined, vlan layer guaranteed to exist
        (p->proto_bits & PROTO_BIT__VLAN) ? layer::get_vlan_layer(p)->vid() : 0,
        (p->proto_bits & PROTO_BIT__MPLS) ? p->ptrs.mplsHdr.label : 0,
        *p->pkth);
}

FlowKey* Stream::get_flow_key(Packet* p)
{
    FlowKey* key = (FlowKey*)snort_calloc(sizeof(*key));
    populate_flow_key(p, key);
    return key;
}

//-------------------------------------------------------------------------
// app data foo
//-------------------------------------------------------------------------

FlowData* Stream::get_flow_data(
    const FlowKey* key, unsigned flowdata_id)
{
    Flow* flow = get_flow(key);
    if (!flow)
        return nullptr;
    return flow->get_flow_data(flowdata_id);
}

FlowData* Stream::get_flow_data(
    PktType type, IpProtocol proto,
    const SfIp* srcIP, uint16_t srcPort,
    const SfIp* dstIP, uint16_t dstPort,
    uint16_t vlan, uint32_t mplsId,
    uint32_t addressSpaceID, unsigned flowdata_id,
    int16_t ingress_group, int16_t egress_group)
{
    Flow* flow = get_flow(
        type, proto, srcIP, srcPort, dstIP, dstPort,
        vlan, mplsId, addressSpaceID, ingress_group,
        egress_group);

    if (!flow)
        return nullptr;

    return flow->get_flow_data(flowdata_id);
}

FlowData* Stream::get_flow_data(
    PktType type, IpProtocol proto,
    const SfIp* srcIP, uint16_t srcPort,
    const SfIp* dstIP, uint16_t dstPort,
    uint16_t vlan, uint32_t mplsId,
    unsigned flowdata_id, const DAQ_PktHdr_t& pkth)
{
    Flow* flow = get_flow(
        type, proto, srcIP, srcPort, dstIP, dstPort,
        vlan, mplsId, pkth);

    if (!flow)
        return nullptr;

    return flow->get_flow_data(flowdata_id);
}

//-------------------------------------------------------------------------
//-------------------------------------------------------------------------
// session status
//-------------------------------------------------------------------------

void Stream::check_flow_closed(Packet* p)
{
    Flow* flow = p->flow;

    if ( !flow or (flow->session_state & STREAM_STATE_RELEASING) )
        return;

    flow->session_state |= STREAM_STATE_RELEASING;

    if (flow->session_state & STREAM_STATE_CLOSED)
    {
        assert(flow_con);

        // Will no longer have flow so save use_direct_inject state on packet.
        if ( flow->flags.use_direct_inject )
            p->packet_flags |= PKT_USE_DIRECT_INJECT;

        p->flow = nullptr;

        // this will get called on each onload
        // eventually all onloads will occur and delete will be called
        if ( not flow->is_suspended() )
        {
            flow_con->release_flow(flow, PruneReason::NONE);
            return;
        }
    }
    else if (flow->session_state & STREAM_STATE_BLOCK_PENDING)
    {
        flow->session->clear();
        flow->free_flow_data();
        flow->set_state(Flow::FlowState::BLOCK);

        if ( !(p->packet_flags & PKT_STATELESS) )
        {
            drop_traffic(p, SSN_DIR_BOTH);
            p->active->set_drop_reason("stream");
            if (PacketTracer::is_active())
                PacketTracer::log("Stream: pending block, drop\n");
        }
        flow->clear_session_state(STREAM_STATE_BLOCK_PENDING);
    }

    flow->session_state &= ~STREAM_STATE_RELEASING;
}

int Stream::ignore_flow(
    const Packet* ctrlPkt, PktType type, IpProtocol ip_proto,
    const SfIp* srcIP, uint16_t srcPort,
    const SfIp* dstIP, uint16_t dstPort,
    char direction, FlowData* fd)
{
    assert(flow_con);

    return flow_con->add_expected_ignore(
        ctrlPkt, type, ip_proto, srcIP, srcPort, dstIP, dstPort, direction, fd);
}

void Stream::stop_inspection(
    Flow* flow, Packet* p, char dir,
    int32_t /*bytes*/, int /*response*/)
{
    assert(flow && flow->session);

    debug_logf(stream_trace, TRACE_BASE, p, "stop inspection on flow, dir %s \n",
        dir == SSN_DIR_BOTH ? "BOTH" :
        ((dir == SSN_DIR_FROM_CLIENT) ? "FROM_CLIENT" : "FROM_SERVER"));

    switch (dir)
    {
    case SSN_DIR_BOTH:
    case SSN_DIR_FROM_CLIENT:
    case SSN_DIR_FROM_SERVER:
        flow->ssn_state.ignore_direction = dir;
        break;
    }

    /* Flush any queued data on the client and/or server */
    if (flow->pkt_type == PktType::TCP)
    {
        if (flow->ssn_state.ignore_direction & SSN_DIR_FROM_CLIENT)
            flow->session->flush_client(p);

        if (flow->ssn_state.ignore_direction & SSN_DIR_FROM_SERVER)
            flow->session->flush_server(p);
    }

    /* FIXIT-M handle bytes/response parameters */

    DetectionEngine::disable_all(p);
    flow->set_state(Flow::FlowState::ALLOW);
}

uint32_t Stream::get_packet_direction(Packet* p)
{
    if (!p || !(p->flow))
        return 0;

    p->flow->set_direction(p);

    return (p->packet_flags & (PKT_FROM_SERVER|PKT_FROM_CLIENT));
}

void Stream::drop_traffic(const Packet* p, char dir)
{
    Flow* flow = p->flow;

    if ( !flow )
        return;

    if ((dir & SSN_DIR_FROM_CLIENT) && !(flow->ssn_state.session_flags & SSNFLAG_DROP_CLIENT))
        flow->ssn_state.session_flags |= SSNFLAG_DROP_CLIENT;

    if ((dir & SSN_DIR_FROM_SERVER) && !(flow->ssn_state.session_flags & SSNFLAG_DROP_SERVER))
        flow->ssn_state.session_flags |= SSNFLAG_DROP_SERVER;
}

void Stream::block_flow(const Packet* p)
{
    Flow* flow = p->flow;

    if (!flow)
        return;

    // Postpone clear till inspection is completed
    flow->session_state |= STREAM_STATE_BLOCK_PENDING;

    flow->disable_inspection();
}

void Stream::drop_flow(const Packet* p)
{
    Flow* flow = p->flow;

    if (!flow)
        return;

    flow->session_state |= STREAM_STATE_BLOCK_PENDING;
    flow->session->clear();
    flow->set_state(Flow::FlowState::BLOCK);

    flow->disable_inspection();

    if ( !(p->packet_flags & PKT_STATELESS) )
        drop_traffic(p, SSN_DIR_BOTH);

    p->active->set_drop_reason("stream");
    if (PacketTracer::is_active())
        PacketTracer::log("Stream: session has been dropped\n");
}

//-------------------------------------------------------------------------
// misc support
//-------------------------------------------------------------------------

void Stream::init_active_response(const Packet* p, Flow* flow)
{
    if ( !flow )
        return;

    flow->response_count = 1;

    if ( p->context->conf->max_responses > 1 )
        flow->set_expire(p, p->context->conf->min_interval);
}

void Stream::purge_flows()
{
    if ( flow_con )
        flow_con->purge_flows();
}

void Stream::handle_timeouts(bool idle)
{
    timeval cur_time;
    packet_gettimeofday(&cur_time);

    // FIXIT-M batch here or loop vs looping over idle?
    if (flow_con)
    {
        if (idle)
            flow_con->timeout_flows(IDLE_PRUNE_MAX, cur_time.tv_sec);
        else
            flow_con->timeout_flows(1, cur_time.tv_sec);
    }

    int max_remove = idle ? -1 : 1;       // -1 = all eligible
    TcpStreamTracker::release_held_packets(cur_time, max_remove);
}

bool Stream::prune_flows()
{
    if ( !flow_con )
        return false;

    return flow_con->prune_multiple(PruneReason::MEMCAP, false);
}

//-------------------------------------------------------------------------
// app proto id foo
//-------------------------------------------------------------------------

int Stream::set_snort_protocol_id_expected(
    const Packet* ctrlPkt, PktType type, IpProtocol ip_proto,
    const SfIp* srcIP, uint16_t srcPort,
    const SfIp* dstIP, uint16_t dstPort,
    SnortProtocolId snort_protocol_id, FlowData* fd, bool swap_app_direction, bool expect_multi,
    bool bidirectional, bool expect_persist)
{
    assert(flow_con);

    return flow_con->add_expected(
        ctrlPkt, type, ip_proto, srcIP, srcPort, dstIP, dstPort, snort_protocol_id, fd,
        swap_app_direction, expect_multi, bidirectional, expect_persist);
}

void Stream::set_snort_protocol_id_from_ha(
    Flow* flow, const SnortProtocolId snort_protocol_id)
{
    if (!flow )
        return;

    if (flow->ssn_state.snort_protocol_id != UNKNOWN_PROTOCOL_ID)
        return;

    if (flow->ssn_state.ipprotocol == 0)
        set_ip_protocol(flow);

    flow->ssn_state.snort_protocol_id = snort_protocol_id;
    if ( snort_protocol_id != UNKNOWN_PROTOCOL_ID &&
         snort_protocol_id != INVALID_PROTOCOL_ID )
        flow->flags.snort_proto_id_set_by_ha = true;
}

SnortProtocolId Stream::get_snort_protocol_id(Flow* flow)
{
    /* Not caching the source and dest host_entry in the session so we can
     * swap the table out after processing this packet if we need
     * to.  */

    if (!flow)
        return UNKNOWN_PROTOCOL_ID;

    if ( flow->ssn_state.snort_protocol_id == INVALID_PROTOCOL_ID )
        return UNKNOWN_PROTOCOL_ID;

    if (flow->ssn_state.snort_protocol_id != UNKNOWN_PROTOCOL_ID)
        return flow->ssn_state.snort_protocol_id;

    if (flow->ssn_state.ipprotocol == 0)
        set_ip_protocol(flow);

    HostAttriInfo host;
    if (HostAttributesManager::get_host_attributes(flow->server_ip, flow->server_port, &host))
    {
        set_snort_protocol_id_from_ha(flow, host.snort_protocol_id);

        if (flow->ssn_state.snort_protocol_id != UNKNOWN_PROTOCOL_ID)
            return flow->ssn_state.snort_protocol_id;
    }

    if (HostAttributesManager::get_host_attributes(flow->client_ip, flow->client_port, &host))
    {
        set_snort_protocol_id_from_ha(flow, host.snort_protocol_id);

        if (flow->ssn_state.snort_protocol_id != UNKNOWN_PROTOCOL_ID)
            return flow->ssn_state.snort_protocol_id;
    }

    flow->ssn_state.snort_protocol_id = INVALID_PROTOCOL_ID;
    return UNKNOWN_PROTOCOL_ID;
}

SnortProtocolId Stream::set_snort_protocol_id(Flow* flow, SnortProtocolId id, bool is_appid_service)
{
    if (!flow)
        return UNKNOWN_PROTOCOL_ID;

    if (flow->ssn_state.snort_protocol_id != id)
        flow->flags.snort_proto_id_set_by_ha = false;

    flow->ssn_state.snort_protocol_id = id;

    if (!flow->ssn_state.ipprotocol)
        set_ip_protocol(flow);

    if ( !flow->is_proxied() and !flow->flags.snort_proto_id_set_by_ha )
    {
        HostAttributesManager::update_service
            (flow->server_ip, flow->server_port, flow->ssn_state.ipprotocol, id, is_appid_service);
    }

    return id;
}

//-------------------------------------------------------------------------
// splitter foo
//-------------------------------------------------------------------------

void Stream::set_splitter(Flow* flow, bool to_server, StreamSplitter* ss)
{
    assert(flow && flow->session);
    return flow->session->set_splitter(to_server, ss);
}

StreamSplitter* Stream::get_splitter(Flow* flow, bool to_server)
{
    assert(flow && flow->session);
    StreamSplitter* ss = flow->session->get_splitter(to_server);
    return ss;
}

//-------------------------------------------------------------------------
// extra data foo
//-------------------------------------------------------------------------

void Stream::log_extra_data(
    Flow* flow, uint32_t mask, uint32_t id, uint32_t sec)
{
    if ( mask && stream.extra_data_log )
    {
        stream.extra_data_log(
            flow, stream.extra_data_config, stream.xtradata_map,
            stream.xtradata_func_count, mask, id, sec);
    }
}

uint32_t Stream::reg_xtra_data_cb(LogFunction f)
{
    uint32_t i = 0;
    while (i < stream.xtradata_func_count)
    {
        if (stream.xtradata_map[i++] == f)
            return i;
    }
    if ( stream.xtradata_func_count == MAX_LOG_FN)
    {
        return 0;
    }

    stream.xtradata_map[stream.xtradata_func_count++] = f;
    return stream.xtradata_func_count;
}

uint32_t Stream::get_xtra_data_map(LogFunction*& f)
{
    f = stream.xtradata_map;
    return stream.xtradata_func_count;
}

void Stream::reg_xtra_data_log(LogExtraData f, void* config)
{
    const std::lock_guard<std::mutex> xtra_lock(stream_xtra_mutex);
    stream.extra_data_log = f;
    stream.extra_data_config = config;
}

//-------------------------------------------------------------------------
// other foo
//-------------------------------------------------------------------------

uint8_t Stream::get_flow_ttl(Flow* flow, char dir, bool outer)
{
    if ( !flow )
        return 0;

    if ( FROM_CLIENT == dir )
        return outer ? flow->outer_client_ttl : flow->inner_client_ttl;

    return outer ? flow->outer_server_ttl : flow->inner_server_ttl;
}

//-------------------------------------------------------------------------
// flow disposition logic
//-------------------------------------------------------------------------

// *DROP* flags are set to mark the direction(s) for which traffic was
// seen since last reset and then cleared after sending new attempt so
// that we only send in the still active direction(s).
static void active_response(Packet* p, Flow* lwssn)
{
    uint8_t max = p->context->conf->max_responses;

    if ( p->is_from_client() )
        lwssn->session_state |= STREAM_STATE_DROP_CLIENT;
    else
        lwssn->session_state |= STREAM_STATE_DROP_SERVER;

    if ( (lwssn->response_count < max) && lwssn->expired(p) )
    {
        uint32_t delay = p->context->conf->min_interval;
        EncodeFlags flags =
            ( (lwssn->session_state & STREAM_STATE_DROP_CLIENT) &&
            (lwssn->session_state & STREAM_STATE_DROP_SERVER) ) ?
            ENC_FLAG_FWD : 0;  // reverse dir is always true

        p->active->kill_session(p, flags);
        ++lwssn->response_count;
        lwssn->set_expire(p, delay);

        lwssn->clear_session_state(STREAM_STATE_DROP_CLIENT|STREAM_STATE_DROP_SERVER);
    }
}

bool Stream::blocked_flow(Packet* p)
{
    Flow* flow = p->flow;

    if ( !(flow->ssn_state.session_flags & (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)) )
        return false;

    if (
        ((p->is_from_server()) &&
        (flow->ssn_state.session_flags & SSNFLAG_DROP_SERVER)) ||

        ((p->is_from_client()) &&
        (flow->ssn_state.session_flags & SSNFLAG_DROP_CLIENT)) )
    {
        DetectionEngine::disable_content(p);
        p->active->drop_packet(p);
        active_response(p, flow);
        p->active->set_drop_reason("stream");
        if (PacketTracer::is_active())
            PacketTracer::log("Stream: session was already blocked\n");
        return true;
    }
    return false;
}

bool Stream::ignored_flow(Flow* flow, Packet* p)
{
    if (((p->is_from_server()) &&
        (flow->ssn_state.ignore_direction & SSN_DIR_FROM_CLIENT)) ||
        ((p->is_from_client()) &&
        (flow->ssn_state.ignore_direction & SSN_DIR_FROM_SERVER)) )
    {
        DetectionEngine::disable_all(p);
        return true;
    }

    return false;
}

static int StreamExpire(Packet* p, Flow* lwssn)
{
    if ( !lwssn->expired(p) )
        return 0;

    if ( HighAvailabilityManager::in_standby(lwssn) )
        return 1;

    lwssn->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
    lwssn->session_state |= STREAM_STATE_TIMEDOUT;

    return 1;
}

bool Stream::expired_flow(Flow* flow, Packet* p)
{
    if ( (flow->session_state & STREAM_STATE_TIMEDOUT)
        || StreamExpire(p, flow) )
    {
        flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// TCP, UDP, ICMP only
//-------------------------------------------------------------------------

/* This should preferably only be called when ipprotocol is 0. */
void Stream::set_ip_protocol(Flow* flow)
{
    switch (flow->pkt_type)
    {
    case PktType::TCP:
        flow->ssn_state.ipprotocol = SNORT_PROTO_TCP;
        break;

    case PktType::UDP:
        flow->ssn_state.ipprotocol = SNORT_PROTO_UDP;
        break;

    case PktType::ICMP:
        flow->ssn_state.ipprotocol = SNORT_PROTO_ICMP;
        break;

    default:
        break;
    }
}

//-------------------------------------------------------------------------
// TCP only
//-------------------------------------------------------------------------

static bool ok_to_flush(Packet* p)
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return false;

    if ( p->type() != PktType::TCP )
        return false;

    return true;
}

void Stream::flush_client(Packet* p)
{
    if ( !ok_to_flush(p) )
        return;

    if ( p->is_from_client() )
        p->flow->session->flush_talker(p);

    else if ( p->is_from_server() )
        p->flow->session->flush_listener(p);
}

void Stream::flush_server(Packet* p)
{
    if ( !ok_to_flush(p) )
        return;

    if ( p->is_from_client() )
        p->flow->session->flush_listener(p);

    else if ( p->is_from_server() )
        p->flow->session->flush_talker(p);
}

// return true if added
bool Stream::add_flow_alert(
    Flow* flow, Packet* p, uint32_t gid, uint32_t sid)
{
    if ( !flow )
        return false;

    return flow->session->add_alert(p, gid, sid);
}

// return true if gid/sid have already been seen
bool Stream::check_flow_alerted(
    Flow* flow, Packet* p, uint32_t gid, uint32_t sid)
{
    if ( !flow )
        return false;

    return flow->session->check_alerted(p, gid, sid);
}

int Stream::update_flow_alert(
    Flow* flow, Packet* p,
    uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
    assert(flow && flow->session);
    return flow->session->update_alert(p, gid, sid, event_id, event_second);
}

void Stream::set_extra_data(
    Flow* flow, Packet* p, uint32_t flag)
{
    assert(flow && flow->session);
    flow->session->set_extra_data(p, flag);
}

void Stream::disable_reassembly(Flow* flow)
{
    assert(flow && flow->session);
    return flow->session->disable_reassembly(flow);
}

char Stream::get_reassembly_direction(Flow* flow)
{
    assert(flow && flow->session);
    return flow->session->get_reassembly_direction();
}

bool Stream::is_stream_sequenced(Flow* flow, uint8_t dir)
{
    assert(flow && flow->session);
    return flow->session->is_sequenced(dir);
}

int Stream::missing_in_reassembled(Flow* flow, uint8_t dir)
{
    assert(flow && flow->session);
    return flow->session->missing_in_reassembled(dir);
}

bool Stream::missed_packets(Flow* flow, uint8_t dir)
{
    assert(flow && flow->session);
    return flow->session->are_packets_missing(dir);
}

uint16_t Stream::get_mss(Flow* flow, bool to_server)
{
    assert(flow and flow->session and flow->pkt_type == PktType::TCP);

    TcpStreamSession* tcp_session = (TcpStreamSession*)flow->session;
    return tcp_session->get_mss(to_server);
}

uint8_t Stream::get_tcp_options_len(Flow* flow, bool to_server)
{
    assert(flow and flow->session and flow->pkt_type == PktType::TCP);

    TcpStreamSession* tcp_session = (TcpStreamSession*)flow->session;
    return tcp_session->get_tcp_options_len(to_server);
}

bool Stream::set_packet_action_to_hold(Packet* p)
{
    if ( !p or !p->flow or !p->flow->session )
        return false;

    return p->flow->session->set_packet_action_to_hold(p);
}

bool Stream::can_set_no_ack_mode(Flow* flow)
{
    assert(flow and flow->session and flow->pkt_type == PktType::TCP);

    TcpStreamSession* tcp_session = (TcpStreamSession*)flow->session;
    return tcp_session->can_set_no_ack();
}

bool Stream::set_no_ack_mode(Flow* flow, bool on_off)
{
    assert(flow and flow->session and flow->pkt_type == PktType::TCP);

    TcpStreamSession* tcp_session = (TcpStreamSession*)flow->session;
    return tcp_session->set_no_ack(on_off);
}

void Stream::partial_flush(Flow* flow, bool to_server)
{
    if ( flow->pkt_type == PktType::TCP )
    {
        if ( to_server )
            ((TcpStreamSession*)flow->session)->server.perform_partial_flush();
        else
            ((TcpStreamSession*)flow->session)->client.perform_partial_flush();
    }
}

bool Stream::get_held_pkt_seq(Flow* flow, uint32_t& seq)
{
    if (!flow or !flow->session or !(flow->pkt_type == PktType::TCP))
        return false;

    TcpStreamSession* tcp_session = (TcpStreamSession*)flow->session;

    if (tcp_session->held_packet_dir == SSN_DIR_NONE)
        return false;

    if (tcp_session->held_packet_dir == SSN_DIR_FROM_CLIENT)
    {
        seq = tcp_session->server.held_pkt_seq;
        tcp_session->held_packet_dir = SSN_DIR_NONE;
        return true;
    }

    if (tcp_session->held_packet_dir == SSN_DIR_FROM_SERVER)
    {
        seq = tcp_session->client.held_pkt_seq;
        tcp_session->held_packet_dir = SSN_DIR_NONE;
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// pub sub foo
//-------------------------------------------------------------------------

static unsigned stream_pub_id = 0;

void Stream::set_pub_id()
{ stream_pub_id = DataBus::get_id(stream_pub_key); }

unsigned Stream::get_pub_id()
{ return stream_pub_id; }

//-------------------------------------------------------------------------
#ifdef UNIT_TEST
//-------------------------------------------------------------------------

#include "catch/snort_catch.h"
#include "tcp/test/stream_tcp_test_utils.h"

TEST_CASE("Stream API", "[stream_api][stream]")
{
    // initialization code here
    Flow* flow = new Flow;

    SECTION("set/get ignore direction")
    {
        int dir = flow->set_ignore_direction(SSN_DIR_NONE);
        CHECK( ( dir == SSN_DIR_NONE ) );
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_NONE ) );

        dir = flow->set_ignore_direction(SSN_DIR_FROM_CLIENT);
        CHECK( ( dir == SSN_DIR_FROM_CLIENT ) );
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_FROM_CLIENT ) );

        dir = flow->set_ignore_direction(SSN_DIR_FROM_SERVER);
        CHECK( ( dir == SSN_DIR_FROM_SERVER ) );
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_FROM_SERVER ) );

        dir = flow->set_ignore_direction(SSN_DIR_BOTH);
        CHECK( ( dir == SSN_DIR_BOTH ) );
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_BOTH ) );
    }

    SECTION("stop inspection")
    {
        Packet* pkt = get_syn_packet(flow);
        int dir;

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_CLIENT, 0, 0);
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_FROM_CLIENT ) );
        CHECK( ( flow->flow_state == Flow::FlowState::ALLOW ) );

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_SERVER, 0, 0);
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_FROM_SERVER ) );
        CHECK( ( flow->flow_state == Flow::FlowState::ALLOW ) );

        release_packet(pkt);
    }

    SECTION("stop inspection from server - client packet")
    {
        Packet* pkt = get_syn_packet(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_SERVER, 0, 0);
        bool ignored = Stream::ignored_flow(flow, pkt);
        CHECK(ignored);

        release_packet(pkt);
    }

    SECTION("stop inspection from server - server packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_SERVER, 0, 0);
        bool ignored = Stream::ignored_flow(flow, pkt);
        CHECK(!ignored);

        release_packet(pkt);
    }

    SECTION("stop inspection from client - client packet")
    {
        Packet* pkt = get_syn_packet(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_CLIENT, 0, 0);
        bool ignored = Stream::ignored_flow(flow, pkt);
        CHECK(!ignored);

        release_packet(pkt);
    }

    SECTION("stop inspection from client - server packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_CLIENT, 0, 0);
        bool ignored = Stream::ignored_flow(flow, pkt);
        CHECK(ignored);

        release_packet(pkt);
    }

    SECTION("stop inspection both - client packet")
    {
        Packet* pkt = get_syn_packet(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_BOTH, 0, 0);
        bool ignored = Stream::ignored_flow(flow, pkt);
        CHECK(ignored);

        release_packet(pkt);
    }

    SECTION("stop inspection both - server packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_BOTH, 0, 0);
        bool ignored = Stream::ignored_flow(flow, pkt);
        CHECK(ignored);

        release_packet(pkt);
    }

    delete flow;
}

#endif

