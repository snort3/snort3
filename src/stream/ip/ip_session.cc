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

#include "ip_session.h"

#include "profiler/profiler_defs.h"
#include "protocols/packet.h"

#include "ip_defrag.h"
#include "ip_ha.h"
#include "stream_ip.h"

using namespace snort;

const PegInfo ip_pegs[] =
{
    SESSION_PEGS("ip"),
    { CountType::SUM, "total_frags", "total fragments" },
    { CountType::NOW, "current_frags", "current fragments" },
    { CountType::SUM, "max_frags", "max fragments" },
    { CountType::SUM, "reassembled", "reassembled datagrams" },
    { CountType::SUM, "discards", "fragments discarded" },
    { CountType::SUM, "frag_timeouts", "datagrams abandoned" },
    { CountType::SUM, "overlaps", "overlapping fragments" },
    { CountType::SUM, "anomalies", "anomalies detected" },
    { CountType::SUM, "alerts", "alerts generated" },
    { CountType::SUM, "drops", "fragments dropped" },
    { CountType::SUM, "trackers_added", "datagram trackers created" },
    { CountType::SUM, "trackers_freed", "datagram trackers released" },
    { CountType::SUM, "trackers_cleared", "datagram trackers cleared" },
    { CountType::SUM, "trackers_completed", "datagram trackers completed" },
    { CountType::SUM, "nodes_inserted", "fragments added to tracker" },
    { CountType::SUM, "nodes_deleted", "fragments deleted from tracker" },
    { CountType::SUM, "reassembled_bytes", "total reassembled bytes" },
    { CountType::SUM, "fragmented_bytes", "total fragmented bytes" },
    { CountType::END, nullptr, nullptr }
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
            lws->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        }
        else
        {
            lws->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;
        }

        if ( (lws->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
            (lws->ssn_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
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

bool IpSession::setup(Packet* p)
{
    SESSION_STATS_ADD(ip_stats);
    memset(&tracker, 0, sizeof(tracker));

    if ( p->ptrs.decode_flags & DECODE_FRAG )
    {
        ip_stats.trackers_created++;
        ip_stats.current_frags++;
    }
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

