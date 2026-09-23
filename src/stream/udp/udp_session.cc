//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "udp_session.h"

#include "flow/flow_control.h"
#include "flow/session.h"
#include "framework/data_bus.h"
#include "hash/xhash.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"
#include "trace/trace_api.h"

#include "udp_ha.h"
#include "udp_module.h"
#include "stream_udp.h"

using namespace snort;

// NOTE:  sender is assumed to be client
//        responder is assumed to be server

const PegInfo udp_pegs[] =
{
    SESSION_PEGS("udp"),
    { CountType::SUM, "total_bytes", "total number of bytes processed" },
    { CountType::SUM, "ignored", "udp packets ignored" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL UdpStats udpStats;
THREAD_LOCAL ProfileStats udp_perf_stats;

//-------------------------------------------------------------------------

static void UdpSessionCleanup(const Flow* lwssn)
{
    if ( lwssn->ssn_state.session_flags & SSNFLAG_SEEN_SENDER )
        udpStats.released++;
}

//-------------------------------------------------------------------------
// UdpSession methods
//-------------------------------------------------------------------------

UdpSession::UdpSession(Flow* f) : Session(f)
{
    if (flow)
        flow->add_mem(sizeof(*this));
}

UdpSession::~UdpSession()
{
    if (flow)
        flow->sub_mem(sizeof(*this));
}

bool UdpSession::setup(Packet* p)
{
    return setup(p, false);
}

bool UdpSession::setup_after_restart(Packet* p)
{
    return setup(p, true);
}

bool UdpSession::setup(Packet* p, bool is_restart)
{
    ssn_time.tv_sec = p->pkth->ts.tv_sec;
    ssn_time.tv_usec = p->pkth->ts.tv_usec;
    payload_bytes_seen_client = 0;
    payload_bytes_seen_server = 0;
    flow->ssn_state.session_flags |= SSNFLAG_SEEN_SENDER;

    flow->pkt_type = p->type();
    flow->ip_proto = (uint8_t)p->get_ip_proto_next();
    flow->ssn_state.direction = FROM_CLIENT;

    const StreamUdpConfig* pc = get_udp_cfg(flow->ssn_server);
    flow->set_default_session_timeout(pc->session_timeout, false);

    trace_logf(stream_udp_trace, TRACE_UDP_STATE, p,
        "session setup (%s), timeout=%u\n", is_restart ? "restart" : "new",
        pc->session_timeout);

    if ( is_restart )
        udpStats.created++;
    else
        SESSION_STATS_ADD(udpStats)

    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_STATE_CHANGE, p);

    if ( flow->ssn_state.ignore_direction != SSN_DIR_NONE )
    {
        trace_logf(stream_udp_trace, TRACE_UDP_STATE, p,
            "session ignored (ignore_direction=%d)\n", flow->ssn_state.ignore_direction);

        if ( !is_restart )
            udpStats.sessions--; // incremented in SESSION_STATS_ADD
        return false;
    }

    return true;
}

void UdpSession::clear()
{
    UdpSessionCleanup(flow);
    UdpHAManager::process_deletion(*flow);
    flow->clear();
}

void UdpSession::update_direction(
    char dir, const SfIp* ip, uint16_t port)
{
    if (flow->client_ip.equals(*ip) && (flow->client_port == port))
    {
        if ((dir == SSN_DIR_FROM_CLIENT) && (flow->ssn_state.direction == FROM_CLIENT))
        {
            // Direction already set as CLIENT
            return;
        }
    }
    else if (flow->server_ip.equals(*ip) && (flow->server_port == port))
    {
        if ((dir == SSN_DIR_FROM_SERVER) && (flow->ssn_state.direction == FROM_SERVER))
        {
            // Direction already set as SERVER
            return;
        }
    }

    // Swap client/server ip, ports, and stats -- leave flow->ssn_state.direction the same
    flow->swap_roles();
}

int UdpSession::process_udp(Flow* lwssn, Packet* p)
{
    assert(lwssn->pkt_type == PktType::UDP);

    if ( Stream::blocked_flow(p) )
        return 0;

    if ( Stream::ignored_flow(lwssn, p) )
    {
        udpStats.ignored++;
        return 0;
    }
    udpStats.total_bytes += p->dsize;
    /* if both seen, mark established */
    if (p->is_from_server())
    {
        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_RESPONDER;
        lwssn->set_ttl(p, false);
        payload_bytes_seen_server += p->dsize;
    }
    else
    {
        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_SENDER;
        lwssn->set_ttl(p, true);
        payload_bytes_seen_client += p->dsize;
    }

    if (!(lwssn->ssn_state.session_flags & SSNFLAG_ESTABLISHED))
    {
        if ((lwssn->ssn_state.session_flags & SSNFLAG_SEEN_SENDER) &&
            (lwssn->ssn_state.session_flags & SSNFLAG_SEEN_RESPONDER))
        {
            lwssn->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;
            DataBus::publish(Stream::get_pub_id(), StreamEventIds::UDP_BIDIRECTIONAL, p);

            trace_logf(stream_udp_trace, TRACE_UDP_STATE, p,
                "established: bidirectional (session_flags=0x%08x)\n",
                lwssn->ssn_state.session_flags);
        }
    }

    if ( lwssn->clouseau )
        lwssn->clouseau->eval(p);

    return 0;
}

int UdpSession::process(Packet* p)
{
    Profile profile(udp_perf_stats);

    // Check if the session is expired.
    // Should be done before we do something with the packet...
    if ( Stream::expired_flow(flow, p) )
    {
        trace_logf(stream_udp_trace, TRACE_UDP_STATE, p,
            "session expired\n");

        udpStats.timeouts++;
        UdpSessionCleanup(flow);
        flow->restart(*p);
        UdpHAManager::process_deletion(*flow);
        if ( !FlowControl::apply_flow_state(flow, p, false) )
            return 0;
    }

    process_udp(flow, p);
    flow->markup_packet_flags(p);

    flow->set_expire(p, flow->default_session_timeout);

    return 0;
}

// cppcheck-suppress unusedFunction ; called virtually through the Session interface
void UdpSession::count_stale_packet()
{
    udpStats.stale_packets++;
}
