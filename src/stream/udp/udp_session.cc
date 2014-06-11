/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

#include "udp_session.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_udp.h"
#include "udp_module.h"
#include "stream/stream.h"
#include "snort_types.h"
#include "snort_debug.h"
#include "detect.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "protocols/packet.h"
#include "flow/flow_control.h"
#include "flow/session.h"
#include "rules.h"
#include "treenodes.h"
#include "snort.h"
#include "packet_io/active.h"
#include "perf_monitor/perf.h"
#include "profiler.h"

/* sender/responder ip/port dereference */
#define udp_sender_ip flow->client_ip
#define udp_sender_port flow->client_port
#define udp_responder_ip flow->server_ip
#define udp_responder_port flow->server_port

static SessionStats gudpStats;
static THREAD_LOCAL SessionStats udpStats;

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats udp_perf_stats;

static PreprocStats* udp_get_profile(const char* key)
{
    if ( !strcmp(key, MOD_NAME) )
        return &udp_perf_stats;

    return nullptr;
}
#endif

//-------------------------------------------------------------------------

static void UdpSessionCleanup(Flow *lwssn)
{
    if (lwssn->s5_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (lwssn->s5_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }

    lwssn->clear();

    udpStats.released++;
    RemoveUDPSession(&sfBase);
}

static int ProcessUdp(
    Flow *lwssn, Packet *p, StreamUdpConfig*, SFXHASH_NODE*)
{
    if (lwssn->protocol != IPPROTO_UDP)  // FIXIT checked by tcp, icmp, and ip too?
    // FIXIT need to free lwssn and get a new one
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Lightweight session not UDP on UDP packet\n"););
        return 0;
    }

    if ( stream.blocked_session(lwssn, p) )
        return 0;

    /* figure out direction of this packet */
    lwssn->set_direction(p);

    if ( stream.ignored_session(lwssn, p) )
        return 0;

    /* if both seen, mark established */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5: Updating on packet from responder\n"););
        lwssn->s5_state.session_flags |= SSNFLAG_SEEN_RESPONDER;
        lwssn->set_ttl(p, false);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Updating on packet from client\n"););
        lwssn->s5_state.session_flags |= SSNFLAG_SEEN_SENDER;
        lwssn->set_ttl(p, true);
    }

    if (!(lwssn->s5_state.session_flags & SSNFLAG_ESTABLISHED))
    {
        if ((lwssn->s5_state.session_flags & SSNFLAG_SEEN_SENDER) &&
            (lwssn->s5_state.session_flags & SSNFLAG_SEEN_RESPONDER))
        {
            lwssn->s5_state.session_flags |= SSNFLAG_ESTABLISHED;
        }
    }

    return 0;
}

//-------------------------------------------------------------------------
// UdpSession methods
//-------------------------------------------------------------------------

UdpSession::UdpSession(Flow* flow) : Session(flow)
{
    ssn_time.tv_sec = 0;
    ssn_time.tv_usec = 0;
}

bool UdpSession::setup(Packet* p)
{
    ssn_time.tv_sec = p->pkth->ts.tv_sec;
    ssn_time.tv_usec = p->pkth->ts.tv_usec;
    flow->s5_state.session_flags |= SSNFLAG_SEEN_SENDER;

    flow->protocol = GET_IPH_PROTO(p);
    flow->s5_state.direction = FROM_SENDER;

    StreamUdpConfig* pc = get_udp_cfg(flow->ssn_server);
    flow->set_expire(p, pc->session_timeout);

    udpStats.created++;
    AddUDPSession(&sfBase);

    if (perfmon_config && (perfmon_config->perf_flags & SFPERF_FLOWIP))
        UpdateFlowIPState(&sfFlow, IP_ARG(flow->client_ip),
            IP_ARG(flow->server_ip), SFS_STATE_UDP_CREATED);

    flow->s5_state.direction = FROM_SENDER;
    IP_COPY_VALUE(flow->client_ip, GET_SRC_IP(p));
    flow->client_port = p->udph->uh_sport;
    IP_COPY_VALUE(flow->server_ip, GET_DST_IP(p));
    flow->server_port = p->udph->uh_dport;

    if ( flow_con->expected_flow(flow, p) )
        return false;

    udpStats.sessions++;
    return true;
}

void UdpSession::clear()
{
    UdpSessionCleanup(flow);
}

void UdpSession::update_direction(
    char dir, snort_ip_p ip, uint16_t port)
{
    snort_ip tmpIp;
    uint16_t tmpPort;

    if (IP_EQUALITY(&udp_sender_ip, ip) && (udp_sender_port == port))
    {
        if ((dir == SSN_DIR_SENDER) && (flow->s5_state.direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if (IP_EQUALITY(&udp_responder_ip, ip) && (udp_responder_port == port))
    {
        if ((dir == SSN_DIR_RESPONDER) && (flow->s5_state.direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }

    /* Swap them -- leave flow->s5_state.direction the same */
    tmpIp = udp_sender_ip;
    tmpPort = udp_sender_port;
    udp_sender_ip = udp_responder_ip;
    udp_sender_port = udp_responder_port;
    udp_responder_ip = tmpIp;
    udp_responder_port = tmpPort;
}

int UdpSession::process(Packet *p)
{
    StreamUdpConfig* pc = get_udp_cfg(flow->ssn_server);
    SFXHASH_NODE *hash_node = NULL;

    PROFILE_VARS;
    PREPROC_PROFILE_START(udp_perf_stats);
    /*
     * Check if the session is expired.
     * Should be done before we do something with the packet...
     */
    if ( stream.expired_session(flow, p) )
    {
        UdpSessionCleanup(flow);
        udpStats.timeouts++;
    }
    ProcessUdp(flow, p, pc, hash_node);
    flow->markup_packet_flags(p);
    flow->set_expire(p, pc->session_timeout);

    PREPROC_PROFILE_END(udp_perf_stats);
    return 0;
}

//-------------------------------------------------------------------------
// api related methods
//-------------------------------------------------------------------------

void udp_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        MOD_NAME, &udp_perf_stats, 0, &totalPerfStats, udp_get_profile);
#endif
}

void udp_sum()
{
    sum_stats((PegCount*)&gudpStats, (PegCount*)&udpStats,
        session_peg_count);
}

void udp_stats()
{
    // FIXIT need to get these before delete flow_con
    //flow_con->get_prunes(IPPROTO_UDP, udpStats.prunes);

    show_stats((PegCount*)&gudpStats, session_pegs, session_peg_count,
        MOD_NAME);
}

void udp_reset()
{
    memset(&udpStats, 0, sizeof(udpStats));
    flow_con->reset_prunes(IPPROTO_UDP);
}

