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

#include "ip_session.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_ip.h"
#include "ip_module.h"
#include "ip_defrag.h"
#include "stream/stream.h"
#include "perf_monitor/perf.h"
#include "flow/flow_control.h"

THREAD_LOCAL SessionStats ipStats;
THREAD_LOCAL ProfileStats ip_perf_stats;

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

void IpSessionCleanup (Flow* lws, FragTracker* tracker)
{
    if ( lws->ssn_server )
    {
        Defrag* d = get_defrag(lws->ssn_server);
        d->cleanup(tracker);
    }

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
                "Stream: Updating on packet from client\n"););

            lws->s5_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream: Updating on packet from server\n"););

            lws->s5_state.session_flags |= SSNFLAG_SEEN_SERVER;
        }

        if ( (lws->s5_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
             (lws->s5_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Stream: session established!\n"););

            lws->s5_state.session_flags |= SSNFLAG_ESTABLISHED;

            lws->set_ttl(p, false);
        }
    }

    // Reset the session timeout.
    {
        StreamIpConfig* pc = get_ip_cfg(lws->ssn_server);
        lws->set_expire(p, pc->session_timeout);
    }
}

//-------------------------------------------------------------------------
// IpSession methods
//-------------------------------------------------------------------------

IpSession::IpSession(Flow* flow) : Session(flow)
{
    memset(&tracker, 0, sizeof(tracker));
}

void IpSession::clear()
{
    IpSessionCleanup(flow, &tracker);
}

bool IpSession::setup (Packet* p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
        "Stream IP session created!\n"););

    ipStats.sessions++;

    IP_COPY_VALUE(flow->client_ip, GET_SRC_IP(p));
    IP_COPY_VALUE(flow->server_ip, GET_DST_IP(p));

#ifdef ENABLE_EXPECTED_IP
    if ( flow_con->expected_session(flow, p))
    {
        PREPROC_PROFILE_END(ip_perf_stats);
        return false;
    }
#endif
    return true;
}

int IpSession::process(Packet* p)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(ip_perf_stats);

    if ( stream.expired_session(flow, p) )
    {
        IpSessionCleanup(flow, &tracker);
        ipStats.timeouts++;

#ifdef ENABLE_EXPECTED_IP
        if ( flow_con->expected_session(flow, p))
        {
            PREPROC_PROFILE_END(ip_perf_stats);
            return 0;
        }
#endif
    }

    flow->set_direction(p);

    if ( stream.blocked_session(flow, p) || stream.ignored_session(flow, p) )
    {
        PREPROC_PROFILE_END(ip_perf_stats);
        return 0;
    }

    if ( p->frag_flag )
    {
        Defrag* d = get_defrag(flow->ssn_server);
        d->process(p, &tracker);
    }

    UpdateSession(p, flow);

    PREPROC_PROFILE_END(ip_perf_stats);
    return 0;
}

