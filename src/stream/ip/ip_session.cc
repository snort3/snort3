//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"

#include "ip_defrag.h"
#include "ip_ha.h"
#include "stream_ip.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

const PegInfo ip_pegs[] =
{
    SESSION_PEGS("ip"),
    { CountType::SUM, "total_bytes", "total number of bytes processed" },
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

static inline void update_session(Packet* p, Flow* lws)
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

            if ( p->type() == PktType::ICMP and p->ptrs.icmph)
            {
                DataBus::publish(Stream::get_pub_id(), StreamEventIds::ICMP_BIDIRECTIONAL, p);
            }
            else
            {
                DataBus::publish(Stream::get_pub_id(), StreamEventIds::IP_BIDIRECTIONAL, p);
            }
        }
    }

    // Reset the session timeout.
    if ( lws->ssn_server )
    {
        lws->set_expire(p, lws->default_session_timeout);
    }
}

//-------------------------------------------------------------------------
// IpSession methods
//-------------------------------------------------------------------------

IpSession::IpSession(Flow* f) : Session(f)
{ }

IpSession::~IpSession()
{ }

void IpSession::clear()
{
    if(tracker.engine)
    {
        //  Only decrement if the tracker was not already cleaned up.
        assert(ip_stats.current_frags);
        ip_stats.current_frags--;
    }

    IpSessionCleanup(flow, &tracker);
    IpHAManager::process_deletion(*flow);
}

bool IpSession::setup(Packet* p)
{
    SESSION_STATS_ADD(ip_stats)
    memset(&tracker, 0, sizeof(tracker));

    StreamIpConfig* pc = get_ip_cfg(flow->ssn_server);
    flow->set_default_session_timeout(pc->session_timeout, false);

    if ( p->ptrs.decode_flags & DECODE_FRAG )
    {
        ip_stats.trackers_created++;
        ip_stats.current_frags++;
    }
    if ( flow->ssn_state.ignore_direction != SSN_DIR_NONE )
    {
        ip_stats.sessions--; // Incremented in SESSION_STATS_ADD
        return false;
    }
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
        IpHAManager::process_deletion(*flow);
    }

    if ( Stream::blocked_flow(p) || Stream::ignored_flow(flow, p) )
        return 0;
    ip_stats.total_bytes += p->dsize;
    if ( p->ptrs.decode_flags & DECODE_FRAG )
    {
        Defrag* d = get_defrag(flow->ssn_server);
        d->process(p, &tracker);
    }

    update_session(p, flow);

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

#ifdef UNIT_TEST

// dummy
class StreamIp : public Inspector
{
public:
    StreamIp(StreamIpConfig*);
    ~StreamIp() override;

    void show(const SnortConfig*) const override;
    NORETURN_ASSERT void eval(Packet*) override;
    StreamIpConfig* config;
    Defrag* defrag;
};

TEST_CASE("IP Session", "[ip_session]")
{
    Flow lws;
    Packet p(false);
    DAQ_PktHdr_t dh = {};
    p.pkth = &dh;

    SECTION("update_session without inspector")
    {
        lws.ssn_server = nullptr;

        update_session(&p, &lws);
        CHECK(lws.expire_time == 0);
    }

    SECTION("update_session with inspector")
    {
        StreamIpConfig* sic = new StreamIpConfig;
        sic->session_timeout = 360;
        lws.set_default_session_timeout(sic->session_timeout, true);
        StreamIp si(sic);
        lws.ssn_server = &si;

        update_session(&p, &lws);
        CHECK(lws.expire_time == 360);
        lws.ssn_server = nullptr;
    }
}
#endif
