//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// extractor_rate_filter_benchmark.cc author vhorbato@cisco.com

#ifdef BENCHMARK_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include "detection/context_switcher.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/flow_config.h"
#include "flow/flow_control.h"
#include "flow/ha.h"
#include "flow/test/flow_stubs.h"
#include "framework/inspector.h"
#include "helpers/policy_switcher.h"
#include "main/analyzer.h"
#include "network_inspectors/extractor/extractor_csv_logger.h"
#include "network_inspectors/extractor/extractor_null_conn.h"
#include "network_inspectors/extractor/extractor_rate_filter.h"
#include "protocols/ip.h"
#include "protocols/layer.h"

using namespace snort;

THREAD_LOCAL class FlowControl* flow_con;

// cppcheck-suppress functionStatic ; stub must match the non-static member signature
const FlowCacheConfig& FlowControl::get_flow_cache_config() const
{
    static FlowCacheConfig config;
    return config;
}

// cppcheck-suppress functionStatic ; stub must match the non-static member signature
bool FlowControl::move_to_allowlist(Flow*) { return true; }
// cppcheck-suppress functionStatic ; stub must match the non-static member signature
void FlowControl::unlink_uni(Flow*) { }
// cppcheck-suppress functionStatic ; stub must match the non-static member signature
void FlowControl::relink_uni(Flow*) { }

namespace snort
{
const SnortConfig* SnortConfig::get_conf() { return nullptr; }
void LogMessage(const char*, ...) { }
// cppcheck-suppress functionStatic ; stub must match the non-static member signature
void Inspector::rem_ref() { }
bool HighAvailabilityManager::active() { return false; }
FlowHAState::FlowHAState() = default;
// cppcheck-suppress functionStatic ; stub must match the non-static member signature
void FlowHAState::reset() { }
void DetectionEngine::onload(const Flow*) { }
Packet* DetectionEngine::set_next_packet(const Packet*, Flow*) { return nullptr; }
IpsContext* DetectionEngine::get_context() { return nullptr; }
DetectionEngine::DetectionEngine() { context = nullptr; }
DetectionEngine::~DetectionEngine() = default;
bool layer::set_outer_ip_api(const Packet* const, ip::IpApi&, int8_t&) { return false; }
// cppcheck-suppress functionStatic ; stub must match the non-static member signature
uint8_t ip::IpApi::ttl() const { return 0; }
const Layer* layer::get_mpls_layer(const Packet* const) { return nullptr; }
}

ContextSwitcher* Analyzer::get_switcher() { return nullptr; }
// cppcheck-suppress functionStatic ; stub must match the non-static member signature
IpsContext* ContextSwitcher::get_context() const { return nullptr; }
PolicySwitcher::PolicySwitcher(Flow*) { }
PolicySwitcher::~PolicySwitcher() { }

TEST_CASE("WEIRD builtin log rate-filter overhead", "[weird-rate-filter-benchmark]")
{
    ExtractorNullConnector connector;
    CsvExtractorLogger logger(&connector, TimeType());
    const auto& log_id = logger.get_id("weird");
    Flow flow;
    Flow sampled_flow;
    Flow multiple_bindings_flow;
    SamplingConfig log_every_event;
    log_every_event.threshold = 0;
    log_every_event.rate = 1;
    log_every_event.duration = 0;
    SamplingConfig sampled;

    const uint64_t binding_id = 1;
    const uint64_t last_binding_id = 8;
    const unsigned gid = 116;
    const unsigned sid = 1;
    const time_t now = 100;

    // Exclude first-use flow-data allocation from steady-state timing.
    (void)builtin::should_log(flow, binding_id, gid, sid, now, log_every_event);

    // Start the sampled case after its initial always-logged threshold.
    for (unsigned occurrence = 0; occurrence < sampled.threshold; ++occurrence)
        (void)builtin::should_log(sampled_flow, binding_id, gid, sid, now, sampled);

    // Populate every key so the timed lookup scans to the last binding instead of inserting it.
    for (uint64_t current_binding_id = binding_id; current_binding_id <= last_binding_id; ++current_binding_id)
        (void)builtin::should_log(multiple_bindings_flow, current_binding_id, gid, sid, now, log_every_event);

    const auto log_record = [&logger, &log_id]()
    {
        logger.open_record();
        logger.add_field("gid", static_cast<uint64_t>(gid));
        logger.add_field("sid", static_cast<uint64_t>(sid));
        logger.add_field("msg", "builtin event");
        logger.close_record(log_id);
    };

    BENCHMARK("builtin log without rate filter")
    {
        log_record();
        return true;
    };

    BENCHMARK("rate filter only (every event logged)")
    {
        return builtin::should_log(flow, binding_id, gid, sid, now, log_every_event);
    };

    BENCHMARK("builtin log with rate filter (every event logged)")
    {
        const bool logged = builtin::should_log(flow, binding_id, gid, sid, now, log_every_event);
        if (logged)
            log_record();
        return logged;
    };

    BENCHMARK("builtin log with rate filter (8 bindings, last match)")
    {
        const bool logged = builtin::should_log(multiple_bindings_flow, last_binding_id, gid, sid, now, log_every_event);
        if (logged)
            log_record();
        return logged;
    };

    BENCHMARK("builtin log with rate filter (default sampling)")
    {
        const bool logged = builtin::should_log(sampled_flow, binding_id, gid, sid, now, sampled);
        if (logged)
            log_record();
        return logged;
    };
}

#endif
