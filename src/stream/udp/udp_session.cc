//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/session.h"
#include "framework/data_bus.h"
#include "hash/xhash.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"

#include "udp_ha.h"
#include "udp_module.h"
#include "stream_udp.h"

using namespace snort;

// NOTE:  sender is assumed to be client
//        responder is assumed to be server

const PegInfo udp_pegs[] =
{
    SESSION_PEGS("udp"),
    { CountType::SUM, "ignored", "udp packets ignored" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL UdpStats udpStats;
THREAD_LOCAL ProfileStats udp_perf_stats;

//-------------------------------------------------------------------------

static void UdpSessionCleanup(Flow* lwssn)
{
    if ( lwssn->ssn_state.session_flags & SSNFLAG_SEEN_SENDER )
        udpStats.released++;
}

static int ProcessUdp(
    Flow* lwssn, Packet* p, StreamUdpConfig*, XHashNode*)
{
    assert(lwssn->pkt_type == PktType::UDP);

    if ( Stream::blocked_flow(lwssn, p) )
        return 0;

    if ( Stream::ignored_flow(lwssn, p) )
    {
        udpStats.ignored++;
        return 0;
    }

    /* if both seen, mark established */
    if (p->is_from_server())
    {
        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_RESPONDER;
        lwssn->set_ttl(p, false);
    }
    else
    {
        lwssn->ssn_state.session_flags |= SSNFLAG_SEEN_SENDER;
        lwssn->set_ttl(p, true);
    }

    if (!(lwssn->ssn_state.session_flags & SSNFLAG_ESTABLISHED))
    {
        if ((lwssn->ssn_state.session_flags & SSNFLAG_SEEN_SENDER) &&
            (lwssn->ssn_state.session_flags & SSNFLAG_SEEN_RESPONDER))
        {
            lwssn->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;
        }
    }

    if ( lwssn->clouseau )
        lwssn->clouseau->eval(p);

    return 0;
}

//-------------------------------------------------------------------------
// UdpSession methods
//-------------------------------------------------------------------------

UdpSession::UdpSession(Flow* flow) : Session(flow)
{
}

bool UdpSession::setup(Packet* p)
{
    ssn_time.tv_sec = p->pkth->ts.tv_sec;
    ssn_time.tv_usec = p->pkth->ts.tv_usec;
    flow->ssn_state.session_flags |= SSNFLAG_SEEN_SENDER;

    flow->pkt_type = p->type();
    flow->ip_proto = (uint8_t)p->get_ip_proto_next();
    flow->ssn_state.direction = FROM_CLIENT;

    StreamUdpConfig* pc = get_udp_cfg(flow->ssn_server);
    flow->set_expire(p, pc->session_timeout);

    SESSION_STATS_ADD(udpStats);

    DataBus::publish(FLOW_STATE_EVENT, p);

    if ( Stream::expected_flow(flow, p) )
    {
        udpStats.sessions--; // incremented in SESSIONS_STATS_ADD
        return false;
    }

    return true;
}

void UdpSession::clear()
{
    UdpSessionCleanup(flow);
    UdpHAManager::process_deletion(flow);
    flow->clear();
}

void UdpSession::update_direction(
    char dir, const SfIp* ip, uint16_t port)
{
    SfIp tmpIp;
    uint16_t tmpPort;

    if (flow->client_ip.equals(*ip) && (flow->client_port == port))
    {
        if ((dir == SSN_DIR_FROM_CLIENT) && (flow->ssn_state.direction == FROM_CLIENT))
        {
            /* Direction already set as CLIENT */
            return;
        }
    }
    else if (flow->server_ip.equals(*ip) && (flow->server_port == port))
    {
        if ((dir == SSN_DIR_FROM_SERVER) && (flow->ssn_state.direction == FROM_SERVER))
        {
            /* Direction already set as SERVER */
            return;
        }
    }

    /* Swap them -- leave flow->ssn_state.direction the same */
    tmpIp = flow->client_ip;
    tmpPort = flow->client_port;
    flow->client_ip = flow->server_ip;
    flow->client_port = flow->server_port;
    flow->server_ip = tmpIp;
    flow->server_port = tmpPort;
}

int UdpSession::process(Packet* p)
{
    Profile profile(udp_perf_stats);

    StreamUdpConfig* pc = get_udp_cfg(flow->ssn_server);
    // Check if the session is expired.
    // Should be done before we do something with the packet...
    if ( Stream::expired_flow(flow, p) )
    {
        udpStats.timeouts++;
        UdpSessionCleanup(flow);
        flow->restart();
        flow->ssn_state.session_flags |= SSNFLAG_SEEN_SENDER;
        udpStats.created++;
        UdpHAManager::process_deletion(flow);
    }

    ProcessUdp(flow, p, pc, nullptr);
    flow->markup_packet_flags(p);
    flow->set_expire(p, pc->session_timeout);

    return 0;
}

