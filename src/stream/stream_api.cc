/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "stream_api.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <sys/time.h>       /* struct timeval */
#include <sys/types.h>      /* u_int*_t */

#include "snort.h"
#include "snort_bounds.h"
#include "util.h"
#include "snort_debug.h"
#include "flow/flow_control.h"
#include "flow/flow_cache.h"
#include "flow/session.h"
#include "stream/stream.h"
#include "tcp/stream_paf.h"
#include "tcp/stream_tcp.h"
#include "udp/stream_udp.h"
#include "icmp/stream_icmp.h"
#include "ip/stream_ip.h"
#include "mstring.h"
#include "protocols/packet.h"
#include "detect.h"
#include "perf_monitor/perf.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "ips_options/ips_flowbits.h"
#include "snort_debug.h"
#include "protocols/layer.h"
#include "protocols/vlan.h"

#include "target_based/sftarget_protocol_reference.h"
#include "target_based/sftarget_hostentry.h"

Stream stream;  // FIXIT-L global for SnortContext

Stream::Stream()
{
    xtradata_func_count = 0;
    extra_data_log = NULL;
    extra_data_config = NULL;
    stream_cb_idx = 1;
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
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    uint8_t ip_protocol, uint16_t vlan, uint32_t mplsId,
    uint16_t addressSpaceId)
{
    FlowKey key;

    key.init(srcIP, srcPort, dstIP, dstPort, ip_protocol, vlan, mplsId, addressSpaceId);

    return get_session(&key);
}

void Stream::populate_session_key(Packet *p, FlowKey *key)
{
    uint16_t addressSpaceId = 0;

    if (!key || !p)
        return;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    addressSpaceId = DAQ_GetAddressSpaceID(p->pkth);
#endif

    key->init(
        p->ptrs.ip_api.get_src(), p->ptrs.sp,
        p->ptrs.ip_api.get_dst(), p->ptrs.dp,
        p->get_ip_proto_next(),
        // if the vlan protocol bit is defined, vlan layer gauranteed to exist
        (p->proto_bits & PROTO_BIT__VLAN) ? layer::get_vlan_layer(p)->vid() : 0,
        (p->proto_bits & PROTO_BIT__MPLS) ? p->ptrs.mplsHdr.label : 0,
        addressSpaceId);
}

FlowKey * Stream::get_session_key(Packet *p)
{
    FlowKey *key = (FlowKey*)calloc(1, sizeof(*key));

    if (!key)
        return NULL;

    populate_session_key(p, key);

    return key;
}

//-------------------------------------------------------------------------
// app data foo
//-------------------------------------------------------------------------

FlowData* Stream::get_application_data_from_key(
    const FlowKey *key, unsigned flow_id)
{
    Flow* flow = get_session(key);
    return flow->get_application_data(flow_id);
}

FlowData* Stream::get_application_data_from_ip_port(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    uint8_t ip_protocol, uint16_t vlan, uint32_t mplsId,
    uint16_t addressSpaceID, unsigned flow_id)
{
    Flow* flow;

    flow = get_session_ptr_from_ip_port(
        srcIP, srcPort, dstIP, dstPort,
        ip_protocol, vlan, mplsId, addressSpaceID);

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

    if (flow->session_state & STREAM5_STATE_CLOSED)
    {
        assert(flow_con);
        flow_con->delete_flow(flow, "closed");
        p->flow = NULL;
    }
}

int Stream::ignore_session(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    uint8_t protocol, char direction,
    uint32_t flow_id)
{
    assert(flow_con);

    FlowData* fd = new FlowData(flow_id);

    return flow_con->add_expected(
        srcIP, srcPort, dstIP, dstPort, protocol, direction, fd);
}

void Stream::stop_inspection(
    Flow *flow, Packet *p, char dir,
    int32_t /*bytes*/, int /*response*/)
{
    if (!flow)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
        case SSN_DIR_CLIENT:
        case SSN_DIR_SERVER:
            if (flow->ssn_state.ignore_direction != dir)
            {
                flow->ssn_state.ignore_direction = dir;
            }
            break;
    }

    /* Flush any queued data on the client and/or server */
    if (flow->protocol == PktType::TCP)
    {
        if (flow->ssn_state.ignore_direction & SSN_DIR_CLIENT)
        {
            Stream5FlushClient(p, flow);
        }

        if (flow->ssn_state.ignore_direction & SSN_DIR_SERVER)
        {
            Stream5FlushServer(p, flow);
        }
    }

    /* TODO: Handle bytes/response parameters */

    DisableInspection(p);
    flow->set_state(Flow::ALLOW);
}

void Stream::resume_inspection(Flow* flow, char dir)
{
    if (!flow)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
        case SSN_DIR_CLIENT:
        case SSN_DIR_SERVER:
            if (flow->ssn_state.ignore_direction & dir)
            {
                flow->ssn_state.ignore_direction &= ~dir;
            }
            break;
    }

}

void Stream::update_direction(
    Flow*  flow, char dir, const sfip_t *ip, uint16_t port)
{
    if (!flow)
        return;

    flow->session->update_direction(dir, ip, port);
}

uint32_t Stream::get_packet_direction(Packet *p)
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

    if ((dir & SSN_DIR_CLIENT) && !(flow->ssn_state.session_flags & SSNFLAG_DROP_CLIENT))
    {
        flow->ssn_state.session_flags |= SSNFLAG_DROP_CLIENT;
        if ( Active_PacketForceDropped() )
            flow->ssn_state.session_flags |= SSNFLAG_FORCE_BLOCK;
    }

    if ((dir & SSN_DIR_SERVER) && !(flow->ssn_state.session_flags & SSNFLAG_DROP_SERVER))
    {
        flow->ssn_state.session_flags |= SSNFLAG_DROP_SERVER;
        if ( Active_PacketForceDropped() )
            flow->ssn_state.session_flags |= SSNFLAG_FORCE_BLOCK;
    }
}

void Stream::drop_packet(Packet *p)
{
    Flow* flow = p->flow;

    if (!flow)
        return;

    flow->session->clear();
    flow->set_state(Flow::BLOCK);

    if (!(p->packet_flags & PKT_STATELESS))
        drop_traffic(flow, SSN_DIR_BOTH);
}

uint32_t Stream::set_session_flags(Flow* flow, uint32_t flags)
{
    if ( !flow )
        return 0;

    if ((flow->ssn_state.session_flags & flags) != flags)
    {
        flow->ssn_state.session_flags |= flags;
    }
    return flow->ssn_state.session_flags;
}

uint32_t Stream::get_session_flags(Flow* flow)
{
    if ( !flow )
        return 0;

    return flow->ssn_state.session_flags;
}

int Stream::get_ignore_direction(Flow* flow)
{
    if ( !flow )
        return 0;

    return flow->ssn_state.ignore_direction;
}

int Stream::set_ignore_direction(Flow* flow, int ignore_direction)
{
    if ( !flow )
        return 0;

    if (flow->ssn_state.ignore_direction != ignore_direction)
    {
        flow->ssn_state.ignore_direction = ignore_direction;
    }

    return flow->ssn_state.ignore_direction;
}

//-------------------------------------------------------------------------
// misc support
//-------------------------------------------------------------------------

StreamFlowData *Stream::get_flow_data(Packet *p)
{
    Flow* flow = p->flow;

    if (!flow)
        return NULL;

    return flow->flowdata;
}

void Stream::init_active_response(Packet* p, Flow* flow)
{
    if ( !flow ) return;

    flow->response_count = 1;

    if ( snort_conf->max_responses > 1 )
        flow->set_expire(p, snort_conf->min_interval);
}

//-------------------------------------------------------------------------
// app proto id foo
//-------------------------------------------------------------------------

int Stream::set_application_protocol_id_expected(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    uint8_t protocol, int16_t appId,
    FlowData* fd) 
{
    assert(flow_con);

    return flow_con->add_expected(
        srcIP, srcPort, dstIP, dstPort, protocol, appId, fd);
}

void Stream::set_application_protocol_id_from_host_entry(
    Flow* flow, const HostAttributeEntry *host_entry, int direction)
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

    if (direction == SSN_DIR_SERVER)
    {
        application_protocol = getApplicationProtocolId(
            host_entry, flow->ssn_state.ipprotocol,
            flow->server_port, SFAT_SERVICE);
    }
    else
    {
        application_protocol = getApplicationProtocolId(
            host_entry, flow->ssn_state.ipprotocol,
            flow->client_port, SFAT_SERVICE);

        if ( application_protocol &&
            (flow->ssn_state.session_flags & SSNFLAG_MIDSTREAM) )
            flow->ssn_state.session_flags |= SSNFLAG_CLIENT_SWAP;
    }

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
    HostAttributeEntry *host_entry = NULL;
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
        set_application_protocol_id_from_host_entry(flow, host_entry, SSN_DIR_SERVER);

        if (flow->ssn_state.application_protocol != 0)
        {
            return flow->ssn_state.application_protocol;
        }
    }

    host_entry = SFAT_LookupHostEntryByIP(&flow->client_ip);

    if (host_entry)
    {
        set_application_protocol_id_from_host_entry(flow, host_entry, SSN_DIR_CLIENT);

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

    SFAT_UpdateApplicationProtocol(
        &flow->server_ip, flow->server_port,
        flow->ssn_state.ipprotocol, id);

    return id;
}

//-------------------------------------------------------------------------
// splitter foo
//-------------------------------------------------------------------------

bool Stream::is_paf_active(Flow* flow, bool to_server)
{
    return Stream5IsPafActiveTcp(flow, to_server);
}

void Stream::set_splitter(Flow* flow, bool to_server, StreamSplitter* ss)
{
    return Stream5SetSplitterTcp(flow, to_server, ss);
}

StreamSplitter* Stream::get_splitter(Flow* flow, bool to_server)
{
    return Stream5GetSplitterTcp(flow, to_server);
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
    while(i < xtradata_func_count)
    {
        if(xtradata_map[i++] == f)
        {
            return i;
        }
    }
    if ( xtradata_func_count == MAX_LOG_FN)
        return 0;
    xtradata_map[xtradata_func_count++] = f;
    return xtradata_func_count;
}

uint32_t Stream::get_xtra_data_map(LogFunction **f)
{
    if(f)
    {
        *f = xtradata_map;
        return xtradata_func_count;
    }
    else
        return 0;
}

void Stream::reg_xtra_data_log(LogExtraData f, void *config)
{
    extra_data_log = f;
    extra_data_config = config;
}

//-------------------------------------------------------------------------
// event foo
//-------------------------------------------------------------------------

unsigned Stream::register_event_handler(Stream_Callback cb)
{
    unsigned id;

    for ( id = 1; id < stream_cb_idx; id++ )
    {
        if ( stream_cb[id] == cb )
            break;
    }
    if ( id == MAX_EVT_CB )
        return 0;

    if ( id == stream_cb_idx )
        stream_cb[stream_cb_idx++] = cb;

    return id;
}

bool Stream::set_event_handler(
    Flow* flow, unsigned id, Stream_Event se)
{
    if ( se >= SE_MAX || flow->handler[se] )
        return false;

    flow->handler[se] = id;
    return true;
}

void Stream::call_handler (Packet* p, unsigned id)
{
    assert(id && id < stream_cb_idx && stream_cb[id]);
    stream_cb[id](p);
}

//-------------------------------------------------------------------------
// other foo
//-------------------------------------------------------------------------

uint8_t Stream::get_session_ttl(Flow* flow, char dir, bool outer)
{
    if ( !flow )
        return 0;

    if ( SSN_DIR_CLIENT == dir )
        return outer ? flow->outer_client_ttl : flow->inner_client_ttl;

    return outer ? flow->outer_server_ttl : flow->inner_server_ttl;
}

//-------------------------------------------------------------------------
// flow disposition logic
//-------------------------------------------------------------------------

// *DROP* flags are set to mark the direction(s) for which traffic was
// seen since last reset and then cleared after sending new attempt so
// that we only send in the still active direction(s).
static void active_response(Packet* p, Flow *lwssn)
{
    uint8_t max = snort_conf->max_responses;

    if ( p->packet_flags & PKT_FROM_CLIENT )
        lwssn->session_state |= STREAM5_STATE_DROP_CLIENT;
    else
        lwssn->session_state |= STREAM5_STATE_DROP_SERVER;

    if ( (lwssn->response_count < max) && lwssn->get_expire(p) )
    {
        uint32_t delay = snort_conf->min_interval;
        EncodeFlags flags =
            ( (lwssn->session_state & STREAM5_STATE_DROP_CLIENT) &&
              (lwssn->session_state & STREAM5_STATE_DROP_SERVER) ) ?
            ENC_FLAG_FWD : 0;  // reverse dir is always true

        Active_KillSession(p, &flags);
        ++lwssn->response_count;
        lwssn->set_expire(p, delay);

        lwssn->session_state &= ~(STREAM5_STATE_DROP_CLIENT|STREAM5_STATE_DROP_SERVER);
    }
}

bool Stream::blocked_session (Flow* flow, Packet* p)
{
    if ( !(flow->ssn_state.session_flags & (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)) )
        return false;

    if (
        ((p->packet_flags & PKT_FROM_SERVER) &&
            (flow->ssn_state.session_flags & SSNFLAG_DROP_SERVER)) ||

        ((p->packet_flags & PKT_FROM_CLIENT) &&
            (flow->ssn_state.session_flags & SSNFLAG_DROP_CLIENT)) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Blocking %s packet as session was blocked\n",
            p->packet_flags & PKT_FROM_SERVER ?  "server" : "client"););

        DisableDetect(p);
        Active_DropPacket();
        active_response(p, flow);
        return true;
    }
    return false;
}

bool Stream::ignored_session (Flow* flow, Packet* p)
{
    if (
        ((p->packet_flags & PKT_FROM_SERVER) &&
            (flow->ssn_state.ignore_direction & SSN_DIR_CLIENT)) ||

        ((p->packet_flags & PKT_FROM_CLIENT) &&
            (flow->ssn_state.ignore_direction & SSN_DIR_SERVER)) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5 Ignoring packet from %d. Session marked as ignore\n",
            p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););

        DisableInspection(p);
        return true;
    }

    return false;
}

static int Stream5ExpireSession(Flow *lwssn)
{
    sfBase.iStreamTimeouts++;
    lwssn->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
    lwssn->session_state |= STREAM5_STATE_TIMEDOUT;

    return 1;
}

static int Stream5Expire(Packet *p, Flow *lwssn)
{
    if ( lwssn->expired(p) )
    {
        /* Expiration time has passed. */
        return Stream5ExpireSession(lwssn);
    }

    return 0;
}

bool Stream::expired_session (Flow* flow, Packet* p)
{
    if ( (flow->session_state & STREAM5_STATE_TIMEDOUT)
        || Stream5Expire(p, flow) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Stream5 IP session timeout!\n"););
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
    switch (flow->protocol)
    {
    case PktType::TCP:
        flow->ssn_state.ipprotocol = protocolReferenceTCP;
        break;

    case PktType::UDP:
        flow->ssn_state.ipprotocol = protocolReferenceUDP;
        break;

    case PktType::ICMP:
        flow->ssn_state.ipprotocol = protocolReferenceICMP;
        break;

    default:
        break;
    }
}

//-------------------------------------------------------------------------
// TCP only
//-------------------------------------------------------------------------

int Stream::response_flush_stream(Packet *p)
{
    Flow* flow;

    if ((p == NULL) || (p->flow == NULL))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush NULL packet or session\n"););
        return 0;
    }

    flow = p->flow;

    if ((flow->protocol != PktType::TCP) ||
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on rebuilt packets\n"););
        return 0;
    }

    /* Flush the talker queue -- this is the opposite side that
     * the packet gets inserted into */
    Stream5FlushTalker(p, flow);

    return 0;
}

// return true if added
bool Stream::add_session_alert(
    Flow *flow, Packet *p, uint32_t gid, uint32_t sid)
{
    if ( !flow )
        return false;

    return flow->session->add_alert(p, gid, sid);
}

// return true if gid/sid have already been seen
bool Stream::check_session_alerted(
    Flow *flow, Packet *p, uint32_t gid, uint32_t sid)
{
    if ( !flow )
        return false;

    return flow->session->check_alerted(p, gid, sid);
}

int Stream::update_session_alert(
    Flow *flow, Packet *p,
    uint32_t gid, uint32_t sid,
    uint32_t event_id, uint32_t event_second)
{
    if ( !flow )
        return 0;

    /* Don't need to do this for other protos because they don't
       do any reassembly. */
    if ( p->type() != PktType::TCP )
        return 0;

    return Stream5UpdateSessionAlertTcp(flow, p, gid, sid, event_id, event_second);
}

void Stream::set_extra_data(
    Flow* pv, Packet* p, uint32_t flag)
{
    Flow* flow = (Flow*)pv;

    if ( !flow )
        return;

    Stream5SetExtraDataTcp(flow, p, flag);
}

// FIXIT-L get pv/flow from packet directly?
void Stream::clear_extra_data(
    Flow* pv, Packet* p, uint32_t flag)
{
    Flow* flow = (Flow*)pv;

    if ( !flow )
        return;

    Stream5ClearExtraDataTcp(flow, p, flag);
}

int Stream::traverse_reassembled(
    Packet *p, PacketIterator callback, void *userdata)
{
    Flow* flow = p->flow;

    if (!flow || flow->protocol != PktType::TCP)
        return 0;

    /* Only if this is a rebuilt packet */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return 0;

    return GetTcpRebuiltPackets(p, flow, callback, userdata);
}

int Stream::traverse_stream_segments(
    Packet *p, StreamSegmentIterator callback, void *userdata)
{
    Flow* flow = p->flow;

    if ((flow == NULL) || (flow->protocol != PktType::TCP))
        return -1;

    /* Only if this is a rebuilt packet */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return -1;

    return GetTcpStreamSegments(p, flow, callback, userdata);
}

char Stream::get_reassembly_direction(Flow* flow)
{
    if (!flow || flow->protocol != PktType::TCP)
        return SSN_DIR_NONE;

    return Stream5GetReassemblyDirectionTcp(flow);
}

char Stream::is_stream_sequenced(Flow* flow, char dir)
{
    if (!flow || flow->protocol != PktType::TCP)
        return 1;

    return Stream5IsStreamSequencedTcp(flow, dir);
}

int Stream::missing_in_reassembled(Flow* flow, char dir)
{
    if (!flow || flow->protocol != PktType::TCP)
        return SSN_MISSING_NONE;

    return Stream5MissingInReassembledTcp(flow, dir);
}

char Stream::missed_packets(Flow* flow, char dir)
{
    if (!flow || flow->protocol != PktType::TCP)
        return 1;

    return Stream5PacketsMissingTcp(flow, dir);
}

