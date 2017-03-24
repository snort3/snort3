//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "ip_session.h"

#include "profiler/profiler_defs.h"
#include "protocols/packet.h"

#include "ip_defrag.h"
#include "ip_ha.h"
#include "stream_ip.h"

const PegInfo ip_pegs[] =
{
    SESSION_PEGS("ip"),
    { "total_frags", "total fragments" },
    { "current_frags", "current fragments" },
    { "max_frags", "max fragments" },
    { "reassembled", "reassembled datagrams" },
    { "discards", "fragments discarded" },
    { "frag_timeouts", "datagrams abandoned" },
    { "overlaps", "overlapping fragments" },
    { "anomalies", "anomalies detected" },
    { "alerts", "alerts generated" },
    { "drops", "fragments dropped" },
    { "trackers_added", "datagram trackers created" },
    { "trackers_freed", "datagram trackers released" },
    { "trackers_cleared", "datagram trackers cleared" },
    { "trackers_completed", "datagram trackers completed" },
    { "nodes_inserted", "fragments added to tracker" },
    { "nodes_deleted", "fragments deleted from tracker" },
    { "memory_used", "current memory usage in bytes" },
    { "reassembled_bytes", "total reassembled bytes" },
    { "fragmented_bytes", "total fragmented bytes" },
    { nullptr, nullptr }
};

THREAD_LOCAL IpStats ip_stats;
THREAD_LOCAL ProfileStats ip_perf_stats;

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

static void IpSessionCleanup(Flow* lws, FragTracker* tracker)
{
    if ( lws->ssn_server )
    {
        Defrag* d = get_defrag(lws->ssn_server);
        d->cleanup(tracker);
    }

    ip_stats.released++;
    lws->restart();
}

//-------------------------------------------------------------------------
// private packet processing methods
//-------------------------------------------------------------------------

static inline void UpdateSession(Packet* p, Flow* lws)
{
    lws->markup_packet_flags(p);

    if ( !(lws->ssn_state.session_flags & SSNFLAG_ESTABLISHED) )
    {
        if ( p->is_from_client() )
        {
            DebugMessage(DEBUG_STREAM_STATE,
                "Stream: Updating on packet from client\n");

            lws->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        }
        else
        {
            DebugMessage(DEBUG_STREAM_STATE,
                "Stream: Updating on packet from server\n");

            lws->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;
        }

        if ( (lws->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
            (lws->ssn_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
            DebugMessage(DEBUG_STREAM_STATE,
                "Stream: session established!\n");

            lws->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;

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
}

void IpSession::clear()
{
    if(tracker.engine)
    {
        //  Only decrement if the tracker was not already cleaned up.
        assert(ip_stats.current_frags);
        ip_stats.current_frags--;
    }

    IpSessionCleanup(flow, &tracker);
    IpHAManager::process_deletion(flow);
}

bool IpSession::setup(Packet*)
{
    DebugMessage(DEBUG_STREAM,
        "Stream IP session created!\n");

    memset(&tracker, 0, sizeof(tracker));
    SESSION_STATS_ADD(ip_stats);
    ip_stats.trackers_created++;
    ip_stats.current_frags++;

#ifdef ENABLE_EXPECTED_IP
    if ( Stream::expected_flow(flow, p) )
    {
        ip_stats.sessions--; // Incremented in SESSION_STATS_ADD
        MODULE_PROFILE_END(ip_perf_stats);
        return false;
    }
#endif
    return true;
}

int IpSession::process(Packet* p)
{
    Profile profile(ip_perf_stats);

    if ( Stream::expired_flow(flow, p) )
    {
        ip_stats.timeouts++;
        IpSessionCleanup(flow, &tracker);

#ifdef ENABLE_EXPECTED_IP
        if ( Stream::expected_flow(flow, p) )
            return 0;
#endif
        IpHAManager::process_deletion(flow);
    }

    if ( Stream::blocked_flow(flow, p) || Stream::ignored_flow(flow, p) )
        return 0;

    if ( p->ptrs.decode_flags & DECODE_FRAG )
    {
        Defrag* d = get_defrag(flow->ssn_server);
        d->process(p, &tracker);
    }

    UpdateSession(p, flow);

    return 0;
}

bool IpSession::add_alert(Packet*, uint32_t gid, uint32_t sid)
{
    FragTracker* ft = &tracker;

    /* Only track a certain number of alerts per session */
    if ( !ft->engine || ft->alert_count >= MAX_FRAG_ALERTS )
        return false;

    ft->alert_gid[ft->alert_count] = gid;
    ft->alert_sid[ft->alert_count] = sid;
    ft->alert_count++;

    return true;
}

bool IpSession::check_alerted(Packet* p, uint32_t gid, uint32_t sid)
{
    FragTracker* ft = &tracker;

    if ( !ft->engine )
        return false;

    for ( unsigned i = 0; i < ft->alert_count; i++ )
    {
        /*  If this is a rebuilt packet and we've seen this alert before, return
         *  that we have previously alerted on a non-rebuilt packet.
         */
        if ( (p->packet_flags & PKT_REBUILT_FRAG)
            && ft->alert_gid[i] == gid && ft->alert_sid[i] == sid )
        {
            return true;
        }
    }

    return false;
}

