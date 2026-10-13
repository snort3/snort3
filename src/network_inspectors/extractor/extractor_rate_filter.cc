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
// extractor_rate_filter.cc author vhorbato@cisco.com

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_rate_filter.h"

#include <algorithm>
#include <iterator>
#include <mutex>
#include <vector>

#include "flow/flow.h"
#include "flow/flow_data.h"
#include "log/messages.h"

using namespace snort;
using namespace std;

namespace builtin
{

static const unsigned flow_data_id = FlowData::create_flow_data_id();
static constexpr size_t max_rate_entries = 512;
static once_flag entries_limit_once;

struct WeirdRateKey
{
    uint64_t binding_id;
    unsigned gid;
    unsigned sid;
};

struct WeirdRateEntry
{
    WeirdRateKey key{ };
    uint32_t threshold_count = 0;
    uint32_t rate_count = 0;
    time_t duration_start = 0;
};

class RateFilterFlowData : public FlowData
{
public:
    RateFilterFlowData() : FlowData(builtin::flow_data_id) { }

    FLOW_DATA_SIZE_OF_EXTRA(RateFilterFlowData, entries.capacity() * sizeof(WeirdRateEntry))

    bool should_log(uint64_t binding_id, unsigned gid, unsigned sid, time_t now,
        const SamplingConfig& config)
    {
        const auto matches = [binding_id, gid, sid](const WeirdRateEntry& entry)
        {
            return entry.key.binding_id == binding_id
                and entry.key.gid == gid
                and entry.key.sid == sid;
        };

        auto entry = find_if(entries.begin(), entries.end(), matches);

        if (entry == entries.end())
        {
            if (entries.size() >= max_rate_entries)
            {
                call_once(entries_limit_once, []()
                {
                    LogMessage("extractor: WEIRD rate filter reached the per-flow entry limit; "
                        "untracked event keys will be logged without rate filtering\n");
                });
                return true;
            }

            const size_t old_capacity = entries.capacity();

            entries.push_back({{binding_id, gid, sid}, 0, 0, now});
            account_capacity_growth(old_capacity);
            entry = prev(entries.end());
        }
        else if (config.duration and now >= entry->duration_start
            and now - entry->duration_start >= config.duration)
        {
            entry->duration_start = now;
            entry->threshold_count = 0;
            entry->rate_count = 0;
        }

        if (entry->threshold_count < config.threshold)
        {
            ++entry->threshold_count;
            return true;
        }

        if (++entry->rate_count == config.rate)
        {
            entry->rate_count = 0;
            return true;
        }

        return false;
    }

private:
    void account_capacity_growth(size_t old_capacity)
    {
        if (owner_flow and entries.capacity() > old_capacity)
            owner_flow->add_mem((entries.capacity() - old_capacity) * sizeof(WeirdRateEntry));
    }

    vector<WeirdRateEntry> entries;
};

static RateFilterFlowData& get_rate_filter(Flow& flow)
{
    auto* state = static_cast<RateFilterFlowData*>(flow.get_flow_data(flow_data_id));
    if (!state)
    {
        state = new RateFilterFlowData;
        flow.set_flow_data(state);
    }

    return *state;
}

bool should_log(Flow& flow, uint64_t binding_id, unsigned gid, unsigned sid, time_t now,
    const SamplingConfig& config)
{
    return get_rate_filter(flow).should_log(binding_id, gid, sid, now, config);
}

}

#if defined(UNIT_TEST) && !defined(CATCH_TEST_BUILD)

#include "catch/snort_catch.h"

TEST_CASE("WEIRD rate filter sampling", "[extractor][weird-rate-filter]")
{
    builtin::RateFilterFlowData state;
    SamplingConfig config;

    for (unsigned occurrence = 1; occurrence <= 2025; ++occurrence)
    {
        const bool expected = occurrence <= 25 or occurrence == 1025 or occurrence == 2025;
        const bool logged = state.should_log(1, 2, 3, 100, config);
        CHECK(logged == expected);
    }
}

TEST_CASE("WEIRD rate filter default duration", "[extractor][weird-rate-filter]")
{
    builtin::RateFilterFlowData state;
    SamplingConfig config;

    for (unsigned occurrence = 0; occurrence < config.threshold; ++occurrence)
        (void)state.should_log(1, 2, 3, 100, config);

    bool logged = state.should_log(1, 2, 3, 699, config);
    CHECK_FALSE(logged);

    logged = state.should_log(1, 2, 3, 700, config);
    CHECK(logged);
}

TEST_CASE("WEIRD rate filter custom policy", "[extractor][weird-rate-filter]")
{
    builtin::RateFilterFlowData state;
    SamplingConfig config;
    config.threshold = 2;
    config.rate = 3;
    config.duration = 60;

    for (unsigned occurrence = 1; occurrence <= 8; ++occurrence)
    {
        const bool expected = occurrence == 1 or occurrence == 2 or occurrence == 5 or occurrence == 8;
        const bool logged = state.should_log(1, 2, 3, 100, config);
        CHECK(logged == expected);
    }

    bool logged = state.should_log(1, 2, 3, 159, config);
    CHECK_FALSE(logged);

    logged = state.should_log(1, 2, 3, 160, config);
    CHECK(logged);

    logged = state.should_log(1, 2, 3, 160, config);
    CHECK(logged);

    logged = state.should_log(1, 2, 3, 160, config);
    CHECK_FALSE(logged);
}

TEST_CASE("WEIRD rate filter zero threshold", "[extractor][weird-rate-filter]")
{
    builtin::RateFilterFlowData state;
    SamplingConfig config;
    config.threshold = 0;
    config.rate = 3;

    for (unsigned occurrence = 1; occurrence <= 6; ++occurrence)
    {
        const bool expected = occurrence == 3 or occurrence == 6;
        const bool logged = state.should_log(1, 2, 3, 100, config);
        CHECK(logged == expected);
    }

    config.rate = 1;
    const bool logged = state.should_log(1, 2, 4, 100, config);
    CHECK(logged);
}

TEST_CASE("WEIRD rate filter duration", "[extractor][weird-rate-filter]")
{
    builtin::RateFilterFlowData state;
    SamplingConfig config;
    config.duration = 60;
    for (unsigned occurrence = 0; occurrence < 25; ++occurrence)
        (void)state.should_log(1, 2, 3, 100, config);

    bool logged = state.should_log(1, 2, 3, 159, config);
    CHECK_FALSE(logged);

    logged = state.should_log(1, 2, 3, 150, config);
    CHECK_FALSE(logged);

    logged = state.should_log(1, 2, 3, 160, config);
    CHECK(logged);

    for (unsigned occurrence = 0; occurrence < 24; ++occurrence)
        (void)state.should_log(1, 2, 3, 219, config);
    logged = state.should_log(1, 2, 3, 219, config);
    CHECK_FALSE(logged);

    logged = state.should_log(1, 2, 3, 220, config);
    CHECK(logged);
}

TEST_CASE("WEIRD rate filter key isolation", "[extractor][weird-rate-filter]")
{
    builtin::RateFilterFlowData state;
    SamplingConfig config;

    for (unsigned occurrence = 1; occurrence <= 25; ++occurrence)
    {
        const bool logged = state.should_log(1, 2, 3, 100, config);
        CHECK(logged);
    }

    bool logged = state.should_log(1, 2, 3, 100, config);
    CHECK_FALSE(logged);

    logged = state.should_log(1, 2, 4, 100, config);
    CHECK(logged);

    logged = state.should_log(1, 3, 3, 100, config);
    CHECK(logged);

    logged = state.should_log(2, 2, 3, 100, config);
    CHECK(logged);
}

TEST_CASE("WEIRD rate filter binding policies", "[extractor][weird-rate-filter]")
{
    builtin::RateFilterFlowData state;
    SamplingConfig first;
    first.threshold = 1;
    first.rate = 2;
    first.duration = 0;
    SamplingConfig second;
    second.threshold = 2;
    second.rate = 3;
    second.duration = 60;

    for (unsigned occurrence = 1; occurrence <= 6; ++occurrence)
    {
        const bool first_expected = occurrence == 1 or occurrence == 3 or occurrence == 5;
        const bool first_logged = state.should_log(1, 2, 3, 100, first);
        CHECK(first_logged == first_expected);

        const bool second_expected = occurrence == 1 or occurrence == 2 or occurrence == 5;
        const bool second_logged = state.should_log(2, 2, 3, 100, second);
        CHECK(second_logged == second_expected);
    }

    const bool first_logged = state.should_log(1, 2, 3, 160, first);
    CHECK(first_logged);

    const bool second_logged = state.should_log(2, 2, 3, 160, second);
    CHECK(second_logged);
}

TEST_CASE("WEIRD rate filter entry limit", "[extractor][weird-rate-filter]")
{
    Flow flow;
    SamplingConfig config;
    config.threshold = 1;
    config.rate = 2;
    config.duration = 60;

    for (uint64_t binding_id = 1; binding_id <= builtin::max_rate_entries; ++binding_id)
    {
        const bool logged = builtin::should_log(flow, binding_id, 2, 3, 100, config);
        CHECK(logged);
    }

    const size_t baseline = flow.get_mem_usage();
    for (uint64_t binding_id = builtin::max_rate_entries + 1;
        binding_id <= builtin::max_rate_entries * 2; ++binding_id)
    {
        bool logged = builtin::should_log(flow, binding_id, 2, 3, 100, config);
        CHECK(logged);
        logged = builtin::should_log(flow, binding_id, 2, 3, 100, config);
        CHECK(logged);
        CHECK(flow.get_mem_usage() == baseline);
    }

    bool logged = builtin::should_log(flow, 1, 2, 3, 100, config);
    CHECK_FALSE(logged);
    logged = builtin::should_log(flow, 1, 2, 3, 100, config);
    CHECK(logged);
    logged = builtin::should_log(flow, builtin::max_rate_entries, 2, 3, 160, config);
    CHECK(logged);
    logged = builtin::should_log(flow, 1, 2, 4, 160, config);
    CHECK(logged);
    logged = builtin::should_log(flow, 1, 3, 3, 160, config);
    CHECK(logged);
    CHECK(flow.get_mem_usage() == baseline);

    flow.free_flow_data(builtin::flow_data_id);
    CHECK(flow.get_mem_usage() < baseline);
}

TEST_CASE("WEIRD rate filter flow isolation", "[extractor][weird-rate-filter]")
{
    Flow first_flow;
    Flow second_flow;
    SamplingConfig config;

    for (unsigned occurrence = 1; occurrence <= 25; ++occurrence)
    {
        const bool logged = builtin::get_rate_filter(first_flow).should_log(1, 2, 3, 100, config);
        CHECK(logged);
    }

    bool logged = builtin::get_rate_filter(first_flow).should_log(1, 2, 3, 100, config);
    CHECK_FALSE(logged);

    logged = builtin::get_rate_filter(second_flow).should_log(1, 2, 3, 100, config);
    CHECK(logged);

    const size_t baseline = first_flow.get_mem_usage();
    first_flow.free_flow_data(builtin::flow_data_id);
    CHECK(first_flow.get_mem_usage() < baseline);
}

#endif
