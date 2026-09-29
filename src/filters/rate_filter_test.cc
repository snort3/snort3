//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

// rate_filter_test.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/snort_catch.h"
#include "detection/rules.h"
#include "flow/flow.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "sfip/sf_ip.h"

#include "rate_filter.h"
#include "sfrf.h"

using namespace snort;

#define IP4_CLIENT "1.2.3.4"
#define IP4_SERVER "1.2.3.5"

#define MEM_DEFAULT (16 * 1024 * 1024)

#define RULE_ORIG (-1)
#define RULE_NEW 0

#define GAUGE_COUNT 1

#define MANY_GAUGES 5

#define GAUGE_TIMEOUT 5

static RateFilterConfig* rfc = nullptr;
static SnortConfig* saved_conf = nullptr;
static time_t gauge_time = 0;

static void GaugeAdd(SnortConfig& sc, unsigned seconds)
{
    tSFRFConfigNode cfg;
    cfg.gid = GID_SESSION;
    cfg.sid = SESSION_EVENT_SETUP;
    cfg.tracking = SFRF_TRACK_BY_DST;
    cfg.count = GAUGE_COUNT;
    cfg.seconds = seconds;
    cfg.newAction = (IpsAction::Type)RULE_NEW;
    cfg.timeout = GAUGE_TIMEOUT;
    cfg.applyTo = nullptr;

    CHECK(RateFilter_Create(&sc, rfc, &cfg) == 0);
}

static void GaugeConfig(SnortConfig& sc, unsigned seconds)
{
    gauge_time = 0;
    saved_conf = SnortConfig::get_main_conf();
    SnortConfig::set_conf(&sc);
    set_default_policy(&sc);

    rfc = RateFilter_ConfigNew();
    rfc->memcap = MEM_DEFAULT;
    SFRF_Alloc(rfc->memcap);
    sc.rate_filter_config = rfc;

    GaugeAdd(sc, seconds);
}

static void GaugeInit(SnortConfig& sc)
{
    GaugeConfig(sc, 0);
}

static void GaugeTerm(SnortConfig& sc)
{
    sc.rate_filter_config = nullptr;
    SnortConfig::set_conf(saved_conf);
    SFRF_Delete();
    RateFilter_ConfigFree(rfc);
    rfc = nullptr;
}

static void SetFlowIps(Flow& flow)
{
    flow.client_ip.set(IP4_CLIENT);
    flow.server_ip.set(IP4_SERVER);
}

static int Setup(Flow& flow, const SnortConfig& sc)
{
    int status = RateFilter_SessionEvent(SESSION_EVENT_SETUP, flow, sc, nullptr);

    if ( status >= IpsAction::get_max_types() )
        status -= IpsAction::get_max_types();

    return status;
}

static int GaugeReads(const SfIp& client, const SfIp& server, bool tunnel_carried = false)
{
    // each read is past the revert timeout of the one before, so the gauge is
    // re-evaluated rather than left latched; GaugeConfig() rewinds it per case
    gauge_time += GAUGE_TIMEOUT * 2;

    const PolicyId policy_id = get_inspection_policy()->policy_id;
    SFRFGaugeKeys gauges;

    int status = SFRF_TestThreshold(rfc, GID_SESSION, SESSION_EVENT_SETUP, policy_id,
        &client, &server, gauge_time, SFRF_COUNT_INCREMENT, &gauges, tunnel_carried);

    if ( status >= IpsAction::get_max_types() )
        status -= IpsAction::get_max_types();

    SFRF_ReleaseGauges(gauges);

    return status;
}

TEST_CASE("rate filter gauge count comes back when the flow is reclaimed", "[rate_filter]")
{
    SnortConfig sc;
    GaugeInit(sc);

    SfIp client, server;
    client.set(IP4_CLIENT);
    server.set(IP4_SERVER);

    {
        Flow flow;
        SetFlowIps(flow);

        CHECK(Setup(flow, sc) == RULE_ORIG);

        CHECK(GaugeReads(client, server) == RULE_NEW);
    }

    CHECK(GaugeReads(client, server) == RULE_ORIG);

    GaugeTerm(sc);
}

TEST_CASE("rate filter returns a tunneled gauge to its tunneled counter", "[rate_filter]")
{
    SnortConfig sc;
    GaugeInit(sc);

    SfIp client, server;
    client.set(IP4_CLIENT);
    server.set(IP4_SERVER);

    CHECK(GaugeReads(client, server, true) == RULE_ORIG);
    CHECK(GaugeReads(client, server, true) == RULE_ORIG);
    CHECK(GaugeReads(client, server) == RULE_ORIG);

    GaugeTerm(sc);
}

TEST_CASE("rate filter keeps the count until the flow data is dumped", "[rate_filter]")
{
    SnortConfig sc;
    GaugeInit(sc);

    SfIp client, server;
    client.set(IP4_CLIENT);
    server.set(IP4_SERVER);

    Flow flow;
    SetFlowIps(flow);

    CHECK(Setup(flow, sc) == RULE_ORIG);
    CHECK(GaugeReads(client, server) == RULE_NEW);

    // this is the path Flow::clear() takes when it dumps the flow data; a restart that
    // keeps it leaves the count alone, which the read above covers.  Flow::clear() is
    // not called directly because it needs a packet thread's detection engine
    flow.free_flow_data();
    CHECK(GaugeReads(client, server) == RULE_ORIG);

    GaugeTerm(sc);
}

TEST_CASE("rate filter takes one count per flow, not one per setup", "[rate_filter]")
{
    SnortConfig sc;
    GaugeInit(sc);

    SfIp client, server;
    client.set(IP4_CLIENT);
    server.set(IP4_SERVER);

    {
        Flow flow;
        SetFlowIps(flow);

        CHECK(Setup(flow, sc) == RULE_ORIG);

        Setup(flow, sc);
    }

    CHECK(GaugeReads(client, server) == RULE_ORIG);

    GaugeTerm(sc);
}

TEST_CASE("rate filter releases the count on the allowlist path", "[rate_filter]")
{
    SnortConfig sc;
    GaugeInit(sc);

    SfIp client, server;
    client.set(IP4_CLIENT);
    server.set(IP4_SERVER);

    Flow flow;
    SetFlowIps(flow);

    CHECK(Setup(flow, sc) == RULE_ORIG);
    CHECK(GaugeReads(client, server) == RULE_NEW);

    RateFilter_SessionRelease(flow);
    CHECK(GaugeReads(client, server) == RULE_ORIG);

    RateFilter_SessionRelease(flow);
    CHECK(GaugeReads(client, server) == RULE_ORIG);

    GaugeTerm(sc);
}

TEST_CASE("rate filter counts the keys it holds as flow memory", "[rate_filter]")
{
    SnortConfig sc;
    GaugeInit(sc);

    Flow one;
    SetFlowIps(one);

    const size_t one_base = one.get_mem_usage();

    CHECK(Setup(one, sc) == RULE_ORIG);

    const size_t one_held = one.get_mem_usage() - one_base;

    CHECK(one_held >= GAUGE_COUNT * sizeof(SFRFGaugeKey));

    for ( int i = 1; i < MANY_GAUGES; ++i )
        GaugeAdd(sc, 0);

    Flow many;
    SetFlowIps(many);

    const size_t many_base = many.get_mem_usage();

    Setup(many, sc);

    CHECK((many.get_mem_usage() - many_base) > one_held);

    RateFilter_SessionRelease(one);
    RateFilter_SessionRelease(many);

    CHECK(one.get_mem_usage() == one_base);
    CHECK(many.get_mem_usage() == many_base);

    GaugeTerm(sc);
}

TEST_CASE("rate filter attaches nothing to a setup rate", "[rate_filter]")
{
    SnortConfig sc;

    GaugeConfig(sc, 60);

    Flow flow;
    SetFlowIps(flow);

    CHECK(Setup(flow, sc) == RULE_ORIG);

    RateFilter_SessionRelease(flow);

    CHECK(Setup(flow, sc) == RULE_NEW);

    GaugeTerm(sc);
}
