/****************************************************************************
 *
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *  Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License Version 2 as
 *  published by the Free Software Foundation.  You may not use, modify or
 *  distribute this program under any other version of the GNU General
 *  Public License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/

/*
 * @file    stream_ip.c
 * @author  Russ Combs <rcombs@sourcefire.com>
 */

#include "stream_ip.h"
#include "ip_config.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_io/active.h"
#include "decode.h"
#include "detect.h"
#include "mstring.h"
#include "parser.h"
#include "profiler.h"
#include "sfxhash.h"
#include "snort_types.h"
#include "snort_debug.h"
#include "flow/flow_control.h"
#include "flow/session.h"
#include "stream_ha.h"
#include "stream_common.h"
#include "util.h"
#include "perf_monitor/perf.h"

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats s5IpPerfStats;

static PreprocStats* ip_get_profile(const char* key)
{
    if ( !strcmp(key, "ip") )
        return &s5IpPerfStats;

    return nullptr;
}
#endif

static SessionStats gipStats;
static THREAD_LOCAL SessionStats ipStats;

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

static void Stream5PrintIpConfig (Stream5IpPolicy* policy)
{
    LogMessage("Stream5 IP Policy config:\n");
    LogMessage("    Timeout: %d seconds\n", policy->session_timeout);
}

static void Stream5ParseIpArgs (char* args, Stream5IpPolicy* policy)
{
    char* *toks;
    int num_toks;
    int i;

    policy->session_timeout = S5_DEFAULT_SSN_TIMEOUT;

    if ( !args || !*args )
        return;

    toks = mSplit(args, ",", 0, &num_toks, 0);

    for (i = 0; i < num_toks; i++)
    {
        int s_toks;
        char* *stoks = mSplit(toks[i], " ", 2, &s_toks, 0);

        if (s_toks == 0)
        {
            ParseError("Missing parameter in Stream5 IP config.");
        }

        if(!strcasecmp(stoks[0], "timeout"))
        {
            char* endPtr = NULL;

            if(stoks[1])
            {
                policy->session_timeout = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid timeout in config file.  Integer parameter required.");
            }

            if ((policy->session_timeout > S5_MAX_SSN_TIMEOUT) ||
                (policy->session_timeout < S5_MIN_SSN_TIMEOUT))
            {
                ParseError("Invalid timeout in config file.  Must be between %d and %d",
                    S5_MIN_SSN_TIMEOUT, S5_MAX_SSN_TIMEOUT);
            }
            if (s_toks > 2)
            {
                ParseError("Invalid Stream5 IP Policy option.  Missing comma?");
            }
        }
        else
        {
            ParseError("Invalid Stream5 IP policy option");
        }

        mSplitFree(&stoks, s_toks);
    }

    mSplitFree(&toks, num_toks);
}

void IpSessionCleanup (Flow* lws)
{
    if (lws->s5_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (lws->s5_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }

    lws->clear();
}

//-------------------------------------------------------------------------
// public config methods
//-------------------------------------------------------------------------

void Stream5IpConfigFree (Stream5IpConfig* config)
{
    if (config == NULL)
        return;

    free(config);
}

int Stream5VerifyIpConfig (SnortConfig*, Stream5IpConfig* config)
{
    if (config == NULL)
        return -1;

    return 0;
}

class IpSession : public Session
{
public:
    IpSession(Flow*);

    void* get_policy (void*, Packet*);
    bool setup (Packet*);
    int process(Packet*);
    void clear();
};

Session* get_ip_session(Flow* flow)
{
    return new IpSession(flow);
}

//-------------------------------------------------------------------------
// private packet processing methods
//-------------------------------------------------------------------------

static inline void UpdateSession (Packet* p, Flow* lws)
{
    lws->markup_packet_flags(p);

    if ( !(lws->s5_state.session_flags & SSNFLAG_ESTABLISHED) )
    {

        if ( p->packet_flags & PKT_FROM_CLIENT )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream5: Updating on packet from client\n"););

            lws->s5_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream5: Updating on packet from server\n"););

            lws->s5_state.session_flags |= SSNFLAG_SEEN_SERVER;
        }

        if ( (lws->s5_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
             (lws->s5_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream5: session established!\n"););

            lws->s5_state.session_flags |= SSNFLAG_ESTABLISHED;

            lws->set_ttl(p, false);
        }
    }

    // Reset the session timeout.
    {
        Stream5IpPolicy* policy;
        policy = (Stream5IpPolicy*)lws->policy;
        lws->set_expire(p, policy->session_timeout);
    }
}

//-------------------------------------------------------------------------
// public packet processing method
//-------------------------------------------------------------------------

#ifdef ENABLE_HA
// FIXIT make all ha api the same and eliminate / use virtuals?
static HA_Api ha_ip_api = {
    /*.get_lws = */            Stream::get_session,
    /*.create_session = */     Stream::new_session,
    /*.deactivate_session = */ NULL,
    /*.delete_session = */     Stream::delete_session,
};
#endif

Stream5IpConfig* Stream5ConfigIp(SnortConfig*, char *args)
{
    RegisterPreprocessorProfile(
        "ip", &s5IpPerfStats, 0, &totalPerfStats, ip_get_profile);

    Stream5IpConfig* ip_config =
        (Stream5IpConfig*)SnortAlloc(sizeof(*ip_config));

#ifdef ENABLE_HA
    ha_set_api(IPPROTO_IP, &ha_ip_api);
#endif

    Stream5ParseIpArgs(args, &ip_config->default_policy);

    return ip_config;
}

//-------------------------------------------------------------------------
// IpSession methods
//-------------------------------------------------------------------------

IpSession::IpSession(Flow* flow) : Session(flow) { }

void IpSession::clear()
{
    IpSessionCleanup(flow);
}

bool IpSession::setup (Packet* p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
        "Stream5 IP session created!\n"););

    ipStats.sessions++;

    IP_COPY_VALUE(flow->client_ip, GET_SRC_IP(p));
    IP_COPY_VALUE(flow->server_ip, GET_DST_IP(p));

#ifdef ENABLE_EXPECTED_IP
    if ( flow_con->expected_session(flow, p))
    {
        PREPROC_PROFILE_END(s5IpPerfStats);
        return false;
    }
#endif
    return true;
}

void* IpSession::get_policy (void* pv, Packet*)
{
    return (Stream5IpConfig*)pv;
}

int IpSession::process(Packet* p)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(s5IpPerfStats);

    if ( stream.expired_session(flow, p) )
    {
        IpSessionCleanup(flow);
        ipStats.timeouts++;

#ifdef ENABLE_EXPECTED_IP
        if ( flow_con->expected_session(flow, p))
        {
            PREPROC_PROFILE_END(s5IpPerfStats);
            return 0;
        }
#endif
    }

    flow->set_direction(p);

    if ( stream.blocked_session(flow, p) || stream.ignored_session(flow, p) )
    {
        PREPROC_PROFILE_END(s5IpPerfStats);
        return 0;
    }

    UpdateSession(p, flow);

    PREPROC_PROFILE_END(s5IpPerfStats);
    return 0;
}

void ip_show(Stream5IpConfig* ip_config)
{
    Stream5PrintIpConfig(&ip_config->default_policy);
}

void ip_sum()
{
    sum_stats((PegCount*)&gipStats, (PegCount*)&ipStats,
        session_peg_count);
}

void ip_stats()
{
    // FIXIT need to get these before delete flow_con
    //flow_con->get_prunes(IPPROTO_UDP, ipStats.prunes);

    show_stats((PegCount*)&gipStats, session_pegs, session_peg_count,
        "stream5_ip");
}

void ip_reset_stats()
{
    memset(&ipStats, 0, sizeof(ipStats));
    flow_con->reset_prunes(IPPROTO_IP);
}

