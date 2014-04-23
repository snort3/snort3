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

#include "stream_udp.h"
#include "udp_config.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "snort_debug.h"
#include "detect.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "decode.h"

#include "stream_common.h"
#include "flow/flow_control.h"
#include "flow/session.h"

#include "rules.h"
#include "treenodes.h"
#include "snort.h"
#include "packet_io/active.h"
#include "perf_monitor/perf.h"
#include "profiler.h"
#include "stream_ha.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats s5UdpPerfStats;

static PreprocStats* udp_get_profile(const char* key)
{
    if ( !strcmp(key, "udp") )
        return &s5UdpPerfStats;

    return nullptr;
}
#endif

static SessionStats gudpStats;
static THREAD_LOCAL SessionStats udpStats;

/*  M A C R O S  **************************************************/
/* actions */
#define ACTION_NOTHING                  0x00000000

/* sender/responder ip/port dereference */
#define udp_sender_ip flow->client_ip
#define udp_sender_port flow->client_port
#define udp_responder_ip flow->server_ip
#define udp_responder_port flow->server_port

class UdpSession : public Session
{
public:
    UdpSession(Flow*);

    void* get_policy (void*, Packet*);
    bool setup (Packet*);
    void update_direction(char dir, snort_ip*, uint16_t port);
    int process(Packet*);
    void clear();

public:
    struct timeval ssn_time;
};

Session* get_udp_session(Flow* lws)
{
    return new UdpSession(lws);
}

Stream5UdpConfig::Stream5UdpConfig()
{
    session_timeout = 30;
    flags = 0;
}

//-------------------------------------------------------------------------

static void Stream5PrintUdpConfig(Stream5UdpConfig*pc)
{
    LogMessage("Stream5 UDP config:\n");
    LogMessage("    Timeout: %d seconds\n", pc->session_timeout);

    const char* opt = (pc->flags & STREAM5_CONFIG_IGNORE_ANY) ? "YES" : "NO";
    LogMessage("    Ignore Any -> Any Rules: %s\n", opt);

#ifdef REG_TEST
    LogMessage("    UDP Session Size: %lu\n",sizeof(UdpSession));
#endif
}

#ifdef DEBUG_STREAM5
static void PrintUdpSession(UdpSession *us)
{
    LogMessage("UdpSession:\n");
    LogMessage("    ssn_time:           %lu\n", us->ssn_time.tv_sec);
    LogMessage("    sender IP:          0x%08X\n", us->udp_sender_ip);
    LogMessage("    responder IP:          0x%08X\n", us->udp_responder_ip);
    LogMessage("    sender port:        %d\n", us->udp_sender_port);
    LogMessage("    responder port:        %d\n", us->udp_responder_port);

    LogMessage("    flags:              0x%X\n", us->flow->session_flags);
}
#endif

void UdpSessionCleanup(Flow *lwssn)
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
    Flow *lwssn, Packet *p, Stream5UdpConfig*, SFXHASH_NODE*)
{
    if (lwssn->protocol != IPPROTO_UDP)  // FIXIT checked by tcp, icmp, and ip too?
    // FIXIT need to free lwssn and get a new one
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Lightweight session not UDP on UDP packet\n"););
        return ACTION_NOTHING;
    }

    if ( stream.blocked_session(lwssn, p) )
        return ACTION_NOTHING;

    /* figure out direction of this packet */
    lwssn->set_direction(p);

    if ( stream.ignored_session(lwssn, p) )
        return ACTION_NOTHING;

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

    return ACTION_NOTHING;
}

uint16_t* Stream5GetUdpPortList(void* pv, int& ignore_any)
{
    Stream5Config* pc = (Stream5Config*)pv;
    if ( !pc->udp_config )
        return NULL;
    ignore_any = pc->udp_config->flags & STREAM5_CONFIG_IGNORE_ANY;
    return pc->udp_config->port_filter;
}

void s5UdpSetPortFilterStatus(
    Stream5UdpConfig* udp_config, unsigned short port, uint16_t status)
{
    udp_config->port_filter[port] |= status;
}

void s5UdpUnsetPortFilterStatus(
    Stream5UdpConfig* udp_config, unsigned short port, uint16_t status)
{
    udp_config->port_filter[port] &= ~status;
}

int s5UdpGetPortFilterStatus(
    Stream5UdpConfig* udp_config, unsigned short port)
{
    return (int)udp_config->port_filter[port];
}

bool s5UdpIgnoreAny(Stream5UdpConfig* udp_config)
{
    return ( udp_config->flags & STREAM5_CONFIG_IGNORE_ANY );
}

void Stream5UdpConfigFree(Stream5UdpConfig *config)
{
    if (config == NULL)
        return;

    free(config);
}

#ifdef ENABLE_HA
static HA_Api ha_udp_api = {
    Stream::get_session,
    Stream::new_session,
    NULL, //.deactivate_session 
    Stream::delete_session,
};
#endif

Stream5UdpConfig* Stream5ConfigUdp(SnortConfig*, char*)
{
    RegisterPreprocessorProfile(
        "udp", &s5UdpPerfStats, 0, &totalPerfStats, udp_get_profile);

    Stream5UdpConfig* udp_config =
        (Stream5UdpConfig*)SnortAlloc(sizeof(*udp_config));

#ifdef ENABLE_HA
    ha_set_api(IPPROTO_UDP, &ha_udp_api);
#endif

    return udp_config;
}

int Stream5VerifyUdpConfig(SnortConfig*, Stream5UdpConfig* config)
{
    if (config == NULL)
        return -1; 

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

void* UdpSession::get_policy (void* pv, Packet*)
{
    return pv;
}

bool UdpSession::setup(Packet* p)
{
    ssn_time.tv_sec = p->pkth->ts.tv_sec;
    ssn_time.tv_usec = p->pkth->ts.tv_usec;
    flow->s5_state.session_flags |= SSNFLAG_SEEN_SENDER;

    flow->protocol = GET_IPH_PROTO(p);
    flow->s5_state.direction = FROM_SENDER;

#ifdef DEBUG_STREAM5
    PrintUdpSession(this);
#endif
    Stream5UdpConfig* pc = (Stream5UdpConfig*)flow->policy;
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
    Stream5UdpConfig* pc = (Stream5UdpConfig*)flow->policy;
    SFXHASH_NODE *hash_node = NULL;

    PROFILE_VARS;
    PREPROC_PROFILE_START(s5UdpPerfStats);
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

    PREPROC_PROFILE_END(s5UdpPerfStats);
    return 0;
}

void udp_sum()
{
    sum_stats((PegCount*)&gudpStats, (PegCount*)&udpStats,
        session_peg_count);
}

void udp_show(Stream5UdpConfig* config)
{
    Stream5PrintUdpConfig(config);
}

void udp_stats()
{
    // FIXIT need to get these before delete flow_con
    //flow_con->get_prunes(IPPROTO_UDP, udpStats.prunes);

    show_stats((PegCount*)&gudpStats, session_pegs, session_peg_count,
        "stream5_udp");
}

void udp_reset_stats()
{
    memset(&udpStats, 0, sizeof(udpStats));
    flow_con->reset_prunes(IPPROTO_UDP);
}

