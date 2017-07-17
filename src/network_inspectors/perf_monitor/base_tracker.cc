//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

// base_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "base_tracker.h"  // FIXIT-W Returning null reference (from <vector>)

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#include "utils/util.h"
#endif

using namespace std;

BaseTracker::BaseTracker(PerfConfig* perf)
    : PerfTracker(perf, perf->output == PERF_FILE, PERF_NAME "_base")
{
    for (unsigned i = 0; i < config->modules.size(); i++)
    {
        Module *m = config->modules.at(i);
        IndexVec peg_map = config->mod_peg_idxs.at(i);

        formatter->register_section(m->get_name());

        for (auto const& peg : peg_map)
            formatter->register_field(m->get_pegs()[peg].name, &(m->get_counts()[peg]));
    }
    formatter->finalize_fields();
}

void BaseTracker::process(bool summary)
{
    write();

    for ( auto const& m : config->modules )
        if (!summary)
            m->sum_stats(false);
}

#ifdef UNIT_TEST

class MockModule : public Module
{
public:
    MockModule() : Module("mockery", "mockery")
    {
        counts = (PegCount*)snort_alloc(5 * sizeof(PegCount));

        for( unsigned i = 0; i < 5; i++ )
            counts[i] = i;
    }

    ~MockModule() { snort_free(counts); }

    const PegInfo* get_pegs() const override { return pegs; }

    PegCount* get_counts() const override { return counts; }

    void sum_stats(bool) override {}

    void real_sum_stats() { Module::sum_stats(false); }

private:
    PegCount* counts;

    PegInfo pegs[6] =
    {
        { "zero", ""},
        { "one", ""},
        { "two", ""},
        { "three", ""},
        { "four", ""},
        { nullptr, nullptr }
    };
};

class MockBaseTracker : public BaseTracker
{
public:
    PerfFormatter* output;

    MockBaseTracker(PerfConfig* config) : BaseTracker(config)
    { output = formatter; }
};

TEST_CASE("module stats", "[BaseTracker]")
{
    unsigned pass = 0;
    PegCount expected[2][5] = {
        {0, 2, 4},
        {0, 0, 0}};

    PerfConfig config;
    config.format = PERF_MOCK;

    MockModule mod;
    config.modules.push_back(&mod);
    config.mod_peg_idxs.push_back(IndexVec());
    config.mod_peg_idxs[0].push_back(0);
    config.mod_peg_idxs[0].push_back(2);
    config.mod_peg_idxs[0].push_back(4);

    MockBaseTracker tracker(&config);
    MockFormatter *formatter = (MockFormatter*)tracker.output;

    tracker.reset();
    tracker.process(false);
    CHECK(*formatter->public_values["mockery.zero"].pc == expected[pass][0]);
    CHECK(*formatter->public_values["mockery.two"].pc == expected[pass][1]);
    CHECK(*formatter->public_values["mockery.four"].pc == expected[pass++][2]);
    mod.real_sum_stats();

    tracker.process(false);
    CHECK(*formatter->public_values["mockery.zero"].pc == expected[pass][0]);
    CHECK(*formatter->public_values["mockery.two"].pc == expected[pass][1]);
    CHECK(*formatter->public_values["mockery.four"].pc == expected[pass++][2]);
    mod.real_sum_stats();
}
#endif
