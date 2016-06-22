//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "stream_api.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>

#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "flow/flow_control.h"
#include "flow/flow_cache.h"
#include "flow/session.h"
#include "stream/stream.h"
#include "stream/paf.h"
#include "tcp/tcp_session.h"
#include "tcp/stream_tcp.h"
#include "udp/stream_udp.h"
#include "icmp/stream_icmp.h"
#include "ip/stream_ip.h"
#include "detection/detect.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "ips_options/ips_flowbits.h"
#include "protocols/packet.h"
#include "protocols/layer.h"
#include "protocols/vlan.h"
#include "target_based/snort_protocols.h"
#include "target_based/sftarget_hostentry.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#include "stream/libtcp/stream_tcp_unit_test.h"
#endif

Stream stream;  // FIXIT-L global for SnortContext

Stream::Stream()
{
    xtradata_func_count = 0;
    extra_data_log = NULL;
    extra_data_config = NULL;
}

Stream::~Stream() { }

//-------------------------------------------------------------------------
// session foo
//-------------------------------------------------------------------------

Flow* Stream::get_session(const FlowKey* key)
{ return flow_con->find_flow(key); }

Flow* Stream::new_session(const FlowKey* key)
{ return flow_con->new_flow(key); }

void Stream::delete_session(const FlowKey* key)
{ flow_con->delete_flow(key); }

//-------------------------------------------------------------------------
// key foo
//-------------------------------------------------------------------------

Flow* Stream::get_session_ptr_from_ip_port(
    PktType type, IpProtocol proto,
    const sfip_t* srcIP, uint16_t srcPort,
    const sfip_t* dstIP, uint16_t dstPort,
    uint16_t vlan, uint32_t mplsId, uint16_t addressSpaceId)
{
    FlowKey key;

    key.init(type, proto, srcIP, srcPort, dstIP, dstPort, vlan, mplsId, addressSpaceId);

    return get_session(&key);
}

void Stream::populate_session_key(Packet* p, FlowKey* key)
{
    if (!key || !p)
        return;

    key->init(
        p->type(), p->get_ip_proto_next(),
        p->ptrs.ip_api.get_src(), p->ptrs.sp,
        p->ptrs.ip_api.get_dst(), p->ptrs.dp,
        // if the vlan protocol bit is defined, vlan layer gauranteed to exist
        (p->proto_bits & PROTO_BIT__VLAN) ? layer::get_vlan_layer(p)->vid() : 0,
        (p->proto_bits & PROTO_BIT__MPLS) ? p->ptrs.mplsHdr.label : 0,
        p->pkth->address_space_id);
}

FlowKey* Stream::get_session_key(Packet* p)
{
    FlowKey* key = (FlowKey*)snort_calloc(sizeof(*key));
    populate_session_key(p, key);
    return key;
}

//-------------------------------------------------------------------------
// app data foo
//-------------------------------------------------------------------------

FlowData* Stream::get_application_data_from_key(
    const FlowKey* key, unsigned flow_id)
{
    Flow* flow = get_session(key);
    return flow->get_application_data(flow_id);
}

FlowData* Stream::get_application_data_from_ip_port(
    PktType type, IpProtocol proto,
    const sfip_t* srcIP, uint16_t srcPort,
    const sfip_t* dstIP, uint16_t dstPort,
    uint16_t vlan, uint32_t mplsId,
    uint16_t addressSpaceID, unsigned flow_id)
{
    Flow* flow;

    flow = get_session_ptr_from_ip_port(
        type, proto,
        srcIP, srcPort, dstIP, dstPort,
        vlan, mplsId, addressSpaceID);

    if (!flow)
        return NULL;

    return flow->get_application_data(flow_id);
}

//-------------------------------------------------------------------------
// session status
//-------------------------------------------------------------------------

void Stream::check_session_closed(Packet* p)
{
    Flow* flow = p->flow;

    if (!p || !flow)
        return;

    if (flow->session_state & STREAM_STATE_CLOSED)
    {
        assert(flow_con);
        // FIXIT-L prune reason was actually 'closed'
        flow_con->delete_flow(flow, PruneReason::USER);
        p->flow = nullptr;
    }
}

int Stream::ignore_session(
    const sfip_t* srcIP, uint16_t srcPort,
    const sfip_t* dstIP, uint16_t dstPort,
    PktType protocol, char direction,
    uint32_t flow_id)
{
    assert(flow_con);

    FlowData* fd = new FlowData(flow_id);

    return flow_con->add_expected(
        srcIP, srcPort, dstIP, dstPort, protocol, direction, fd);
}

void Stream::proxy_started(Flow* flow, unsigned dir)
{
    if (!flow)
        return;

    TcpSession* tcpssn = (TcpSession*)flow->session;
    tcpssn->flush();

    if ( dir & SSN_DIR_FROM_SERVER )
        stream.set_splitter(flow, true, new LogSplitter(true));

    if ( dir & SSN_DIR_FROM_CLIENT )
        stream.set_splitter(flow, false, new LogSplitter(false));

    tcpssn->start_proxy();
    flow->set_proxied();
}

void Stream::stop_inspection(
    Flow* flow, Packet* p, char dir,
    int32_t /*bytes*/, int /*response*/)
{
    assert(flow && flow->session);

    switch (dir)
    {
    case SSN_DIR_BOTH:
    case SSN_DIR_FROM_CLIENT:
    case SSN_DIR_FROM_SERVER:
        if (flow->ssn_state.ignore_direction != dir)
        {
            flow->ssn_state.ignore_direction = dir;
        }
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

    DisableInspection();
    flow->set_state(Flow::ALLOW);
}

void Stream::resume_inspection(Flow* flow, char dir)
{
    if (!flow)
        return;

    switch (dir)
    {
    case SSN_DIR_BOTH:
    case SSN_DIR_FROM_CLIENT:
    case SSN_DIR_FROM_SERVER:
        if (flow->ssn_state.ignore_direction & dir)
        {
            flow->ssn_state.ignore_direction &= ~dir;
        }
        break;
    }
}

void Stream::update_direction(
    Flow* flow, char dir, const sfip_t* ip, uint16_t port)
{
    if (!flow)
        return;

    flow->session->update_direction(dir, ip, port);
}

uint32_t Stream::get_packet_direction(Packet* p)
{
    if (!p || !(p->flow))
        return 0;

    p->flow->set_direction(p);

    return (p->packet_flags & (PKT_FROM_SERVER|PKT_FROM_CLIENT));
}

void Stream::drop_traffic(Flow* flow, char dir)
{
    if (!flow)
        return;

    if ((dir & SSN_DIR_FROM_CLIENT) && !(flow->ssn_state.session_flags & SSNFLAG_DROP_CLIENT))
    {
        flow->ssn_state.session_flags |= SSNFLAG_DROP_CLIENT;
        if ( Active::packet_force_dropped() )
            flow->ssn_state.session_flags |= SSNFLAG_FORCE_BLOCK;
    }

    if ((dir & SSN_DIR_FROM_SERVER) && !(flow->ssn_state.session_flags & SSNFLAG_DROP_SERVER))
    {
        flow->ssn_state.session_flags |= SSNFLAG_DROP_SERVER;
        if ( Active::packet_force_dropped() )
            flow->ssn_state.session_flags |= SSNFLAG_FORCE_BLOCK;
    }
}

void Stream::drop_session(const Packet* p)
{
    Flow* flow = p->flow;

    if (!flow)
        return;

    flow->session->clear();
    flow->set_state(Flow::BLOCK);

    if (!(p->packet_flags & PKT_STATELESS))
        drop_traffic(flow, SSN_DIR_BOTH);
}

//-------------------------------------------------------------------------
// misc support
//-------------------------------------------------------------------------

BitOp* Stream::get_flow_bitop(const Packet* p)
{
    Flow* flow = p->flow;

    if (!flow)
        return NULL;

    return flow->bitop;
}

void Stream::init_active_response(const Packet* p, Flow* flow)
{
    if ( !flow )
        return;

    flow->response_count = 1;

    if ( snort_conf->max_responses > 1 )
        flow->set_expire(p, snort_conf->min_interval);
}

//-------------------------------------------------------------------------
// app proto id foo
//-------------------------------------------------------------------------

int Stream::set_application_protocol_id_expected(
    const sfip_t* srcIP, uint16_t srcPort,
    const sfip_t* dstIP, uint16_t dstPort,
    PktType protocol, int16_t appId, FlowData* fd)
{
    assert(flow_con);

    return flow_con->add_expected(
        srcIP, srcPort, dstIP, dstPort, protocol, appId, fd);
}

void Stream::set_application_protocol_id_from_host_entry(
    Flow* flow, const HostAttributeEntry* host_entry, int /*direction*/)
{
    int16_t application_protocol;

    if (!flow || !host_entry)
        return;

    /* Cool, its already set! */
    if (flow->ssn_state.application_protocol != 0)
        return;

    if (flow->ssn_state.ipprotocol == 0)
    {
        set_ip_protocol(flow);
    }

    application_protocol = getApplicationProtocolId(
        host_entry, flow->ssn_state.ipprotocol,
        flow->server_port, SFAT_SERVICE);

#if 0
    // FIXIT-M from client doesn't imply need to swap
    if (direction == FROM_CLIENT)
    {
        if ( application_protocol &&
            (flow->ssn_state.session_flags & SSNFLAG_MIDSTREAM) )
            flow->ssn_state.session_flags |= SSNFLAG_CLIENT_SWAP;
    }
#endif

    if (flow->ssn_state.application_protocol != application_protocol)
    {
        flow->ssn_state.application_protocol = application_protocol;
    }
}

int16_t Stream::get_application_protocol_id(Flow* flow)
{
    /* Not caching the source and dest host_entry in the session so we can
     * swap the table out after processing this packet if we need
     * to.  */
    HostAttributeEntry* host_entry = NULL;
    int16_t protocol = 0;

    if (!flow)
        return protocol;

    if ( flow->ssn_state.application_protocol == -1 )
        return 0;

    if (flow->ssn_state.application_protocol != 0)
        return flow->ssn_state.application_protocol;

    if (flow->ssn_state.ipprotocol == 0)
    {
        set_ip_protocol(flow);
    }

    host_entry = SFAT_LookupHostEntryByIP(&flow->server_ip);
    if (host_entry)
    {
        set_application_protocol_id_from_host_entry(flow, host_entry, FROM_SERVER);

        if (flow->ssn_state.application_protocol != 0)
        {
            return flow->ssn_state.application_protocol;
        }
    }

    host_entry = SFAT_LookupHostEntryByIP(&flow->client_ip);
    if (host_entry)
    {
        set_application_protocol_id_from_host_entry(flow, host_entry, FROM_CLIENT);

        if (flow->ssn_state.application_protocol != 0)
        {
            return flow->ssn_state.application_protocol;
        }
    }

    flow->ssn_state.application_protocol = -1;

    return 0;
}

int16_t Stream::set_application_protocol_id(Flow* flow, int16_t id)
{
    if (!flow)
        return 0;

    if (flow->ssn_state.application_protocol != id)
    {
        flow->ssn_state.application_protocol = id;
    }

    if (!flow->ssn_state.ipprotocol)
        set_ip_protocol(flow);

    if ( !flow->is_proxied() )
    {
        SFAT_UpdateApplicationProtocol(
            &flow->server_ip, flow->server_port,
            flow->ssn_state.ipprotocol, id);
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
    return ( ss and ss->is_paf() ) ? ss : nullptr;
}

bool Stream::is_paf_active(Flow* flow, bool to_server)
{
    assert(flow && flow->session);
    StreamSplitter* ss = flow->session->get_splitter(to_server);
    return ss && ss->is_paf();
}

//-------------------------------------------------------------------------
// extra data foo
//-------------------------------------------------------------------------

void Stream::log_extra_data(
    Flow* flow, uint32_t mask, uint32_t id, uint32_t sec)
{
    if ( mask && extra_data_log )
    {
        extra_data_log(
            flow, extra_data_config, xtradata_map,
            xtradata_func_count, mask, id, sec);
    }
}

uint32_t Stream::reg_xtra_data_cb(LogFunction f)
{
    uint32_t i = 0;
    while (i < xtradata_func_count)
    {
        if (xtradata_map[i++] == f)
        {
            return i;
        }
    }
    if ( xtradata_func_count == MAX_LOG_FN)
        return 0;
    xtradata_map[xtradata_func_count++] = f;
    return xtradata_func_count;
}

uint32_t Stream::get_xtra_data_map(LogFunction** f)
{
    if (f)
    {
        *f = xtradata_map;
        return xtradata_func_count;
    }
    else
        return 0;
}

void Stream::reg_xtra_data_log(LogExtraData f, void* config)
{
    extra_data_log = f;
    extra_data_config = config;
}

//-------------------------------------------------------------------------
// other foo
//-------------------------------------------------------------------------

uint8_t Stream::get_session_ttl(Flow* flow, char dir, bool outer)
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
    uint8_t max = snort_conf->max_responses;

    if ( p->is_from_client() )
        lwssn->session_state |= STREAM_STATE_DROP_CLIENT;
    else
        lwssn->session_state |= STREAM_STATE_DROP_SERVER;

    if ( (lwssn->response_count < max) && lwssn->get_expire(p) )
    {
        uint32_t delay = snort_conf->min_interval;
        EncodeFlags flags =
            ( (lwssn->session_state & STREAM_STATE_DROP_CLIENT) &&
            (lwssn->session_state & STREAM_STATE_DROP_SERVER) ) ?
            ENC_FLAG_FWD : 0;  // reverse dir is always true

        Active::kill_session(p, flags);
        ++lwssn->response_count;
        lwssn->set_expire(p, delay);

        lwssn->session_state &= ~(STREAM_STATE_DROP_CLIENT|STREAM_STATE_DROP_SERVER);
    }
}

bool Stream::blocked_session(Flow* flow, Packet* p)
{
    if ( !(flow->ssn_state.session_flags & (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)) )
        return false;

    if (
        ((p->is_from_server()) &&
        (flow->ssn_state.session_flags & SSNFLAG_DROP_SERVER)) ||

        ((p->is_from_client()) &&
        (flow->ssn_state.session_flags & SSNFLAG_DROP_CLIENT)) )
    {
        DebugFormat(DEBUG_STREAM_STATE,
            "Blocking %s packet as session was blocked\n",
            p->is_from_server() ?  "server" : "client");

        DisableDetect();
        Active::drop_packet(p);
        active_response(p, flow);
        return true;
    }
    return false;
}

bool Stream::ignored_session(Flow* flow, Packet* p)
{
    if (((p->is_from_server()) &&
        (flow->ssn_state.ignore_direction & SSN_DIR_FROM_CLIENT)) ||
        ((p->is_from_client()) &&
        (flow->ssn_state.ignore_direction & SSN_DIR_FROM_SERVER)) )
    {
        DebugFormat(DEBUG_STREAM_STATE,
            "Stream Ignoring packet from %s. Session marked as ignore\n",
            p->is_from_client() ? "sender" : "responder");

        DisableInspection();
        return true;
    }

    return false;
}

static int StreamExpireSession(Flow* lwssn)
{
    lwssn->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
    lwssn->session_state |= STREAM_STATE_TIMEDOUT;

    return 1;
}

static int StreamExpire(Packet* p, Flow* lwssn)
{
    if ( lwssn->expired(p) )
    {
        /* Expiration time has passed. */
        return StreamExpireSession(lwssn);
    }

    return 0;
}

bool Stream::expired_session(Flow* flow, Packet* p)
{
    if ( (flow->session_state & STREAM_STATE_TIMEDOUT)
        || StreamExpire(p, flow) )
    {
        DebugMessage(DEBUG_STREAM, "Stream IP session timeout!\n");
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

void Stream::flush_request(Packet* p)
{
    if ( !ok_to_flush(p) )
        return;

    /* Flush the listener queue -- this is the same side that
     * the packet gets inserted into */
    p->flow->session->flush_listener(p);
}

void Stream::flush_response(Packet* p)
{
    if ( !ok_to_flush(p) )
        return;

    /* Flush the talker queue -- this is the opposite side that
     * the packet gets inserted into */
    p->flow->session->flush_talker(p);
}

// return true if added
bool Stream::add_session_alert(
    Flow* flow, Packet* p, uint32_t gid, uint32_t sid)
{
    if ( !flow )
        return false;

    return flow->session->add_alert(p, gid, sid);
}

// return true if gid/sid have already been seen
bool Stream::check_session_alerted(
    Flow* flow, Packet* p, uint32_t gid, uint32_t sid)
{
    if ( !flow )
        return false;

    return flow->session->check_alerted(p, gid, sid);
}

int Stream::update_session_alert(
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

// FIXIT-L get pv/flow from packet directly?
void Stream::clear_extra_data(
    Flow* flow, Packet* p, uint32_t flag)
{
    assert(flow && flow->session);
    flow->session->clear_extra_data(p, flag);
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

#ifdef UNIT_TEST

#include "framework/cursor.h"

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
        pkt->flow->session = new TcpSession(flow);
        int dir;

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_CLIENT, 0, 0);
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_FROM_CLIENT ) );
        CHECK( ( flow->flow_state == Flow::ALLOW ) );

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_SERVER, 0, 0);
        dir = flow->get_ignore_direction( );
        CHECK( ( dir == SSN_DIR_FROM_SERVER ) );
        CHECK( ( flow->flow_state == Flow::ALLOW ) );

        delete pkt->flow->session;
        delete pkt;
    }

    SECTION("stop inspection from server - client packet")
    {
        Packet* pkt = get_syn_packet(flow);
        pkt->flow->session = new TcpSession(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_SERVER, 0, 0);
        bool ignored = Stream::ignored_session(flow, pkt);
        CHECK(ignored);

        delete pkt->flow->session;
        delete pkt;
    }

    SECTION("stop inspection from server - server packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);
        pkt->flow->session = new TcpSession(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_SERVER, 0, 0);
        bool ignored = Stream::ignored_session(flow, pkt);
        CHECK(!ignored);
        delete pkt->flow->session;
        delete pkt;
    }

    SECTION("stop inspection from client - client packet")
    {
        Packet* pkt = get_syn_packet(flow);
        pkt->flow->session = new TcpSession(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_CLIENT, 0, 0);
        bool ignored = Stream::ignored_session(flow, pkt);
        CHECK(!ignored);

        delete pkt->flow->session;
        delete pkt;
    }

    SECTION("stop inspection from client - server packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);
        pkt->flow->session = new TcpSession(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_FROM_CLIENT, 0, 0);
        bool ignored = Stream::ignored_session(flow, pkt);
        CHECK(ignored);
        delete pkt->flow->session;
        delete pkt;
    }

    SECTION("stop inspection both - client packet")
    {
        Packet* pkt = get_syn_packet(flow);
        pkt->flow->session = new TcpSession(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_BOTH, 0, 0);
        bool ignored = Stream::ignored_session(flow, pkt);
        CHECK(ignored);

        delete pkt->flow->session;
        delete pkt;
    }

    SECTION("stop inspection both - server packet")
    {
        Packet* pkt = get_syn_ack_packet(flow);
        pkt->flow->session = new TcpSession(flow);

        Stream::stop_inspection(flow, pkt, SSN_DIR_BOTH, 0, 0);
        bool ignored = Stream::ignored_session(flow, pkt);
        CHECK(ignored);
        delete pkt->flow->session;
        delete pkt;
    }

    delete flow;
}

#endif

