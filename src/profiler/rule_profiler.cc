//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// rule_profiler.cc author Joel Cornett <jocornet@cisco.com>

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "rule_profiler.h"

//#include <algorithm>
//#include <functional>
//#include <iostream>
//#include <sstream>
//#include <vector>

// this include eventually leads to possible issues with std::chrono:
// 1.  Undefined or garbage value returned to caller (rep count())
// 2.  The left expression of the compound assignment is an uninitialized value.
//     The computed value will also be garbage (duration& operator+=(const duration& __d))
#include "detection/detection_options.h"  // ... FIXIT-W

#include "detection/treenodes.h"
#include "hash/ghash.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "parser/parser.h"
#include "target_based/snort_protocols.h"

#include "profiler_printer.h"
#include "profiler_stats_table.h"
#include "rule_profiler_defs.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

#define s_rule_table_title "rule profile"

static inline OtnState& operator+=(OtnState& lhs, const OtnState& rhs)
{
    lhs.elapsed += rhs.elapsed;
    lhs.elapsed_match += rhs.elapsed_match;
    lhs.checks += rhs.checks;
    lhs.matches += rhs.matches;
    lhs.alerts += rhs.alerts;
    return lhs;
}

namespace rule_stats
{

static const StatsTable::Field fields[] =
{
    { "#", 5, '\0', 0, std::ios_base::left },
    { "gid", 6, '\0', 0, std::ios_base::fmtflags() },
    { "sid", 6, '\0', 0, std::ios_base::fmtflags() },
    { "rev", 4, '\0', 0, std::ios_base::fmtflags() },
    { "checks", 7, '\0', 0, std::ios_base::fmtflags() },
    { "matches", 8, '\0', 0, std::ios_base::fmtflags() },
    { "alerts", 7, '\0', 0, std::ios_base::fmtflags() },
    { "time (us)", 10, '\0', 0, std::ios_base::fmtflags() },
    { "avg/check", 10, '\0', 1, std::ios_base::fmtflags() },
    { "avg/match", 10, '\0', 1, std::ios_base::fmtflags() },
    { "avg/non-match", 14, '\0', 1, std::ios_base::fmtflags() },
    { "timeouts", 9, '\0', 0, std::ios_base::fmtflags() },
    { "suspends", 9, '\0', 0, std::ios_base::fmtflags() },
    { nullptr, 0, '\0', 0, std::ios_base::fmtflags() }
};

struct View
{
    OtnState state;
    SigInfo sig_info;

    hr_duration elapsed() const
    { return state.elapsed; }

    hr_duration elapsed_match() const
    { return state.elapsed_match; }

    hr_duration elapsed_no_match() const
    { return elapsed() - elapsed_match(); }

    uint64_t checks() const
    { return state.checks; }

    uint64_t matches() const
    { return state.matches; }

    uint64_t no_matches() const
    { return checks() - matches(); }

    uint64_t alerts() const
    { return state.alerts; }

    uint64_t timeouts() const
    { return state.latency_timeouts; }

    uint64_t suspends() const
    { return state.latency_suspends; }

    hr_duration time_per(hr_duration d, uint64_t v) const
    {
        if ( v  == 0 )
            return CLOCK_ZERO;

        return hr_duration(d / v);
    }

    hr_duration avg_match() const
    { return time_per(elapsed_match(), matches()); }

    hr_duration avg_no_match() const
    { return time_per(elapsed_no_match(), no_matches()); }

    hr_duration avg_check() const
    { return time_per(elapsed(), checks()); }

    View(const OtnState& otn_state, const SigInfo* si = nullptr) :
        state(otn_state)
    {
        if ( si )
            // FIXIT-L does sig_info need to be initialized otherwise?
            sig_info = *si;
    }
};

static const ProfilerSorter<View> sorters[] =
{
    { "", nullptr },
    {
        "checks",
        [](const View& lhs, const View& rhs)
        { return lhs.checks() >= rhs.checks(); }
    },
    {
        "avg_check",
        [](const View& lhs, const View& rhs)
        { return lhs.avg_check() >= rhs.avg_check(); }
    },
    {
        "total_time",
        [](const View& lhs, const View& rhs)
        { return TO_TICKS(lhs.elapsed()) >= TO_TICKS(rhs.elapsed()); }
    },
    {
        "matches",
        [](const View& lhs, const View& rhs)
        { return lhs.matches() >= rhs.matches(); }
    },
    {
        "no_matches",
        [](const View& lhs, const View& rhs)
        { return lhs.no_matches() >= rhs.no_matches(); }
    },
    {
        "avg_match",
        [](const View& lhs, const View& rhs)
        { return lhs.avg_match() >= rhs.avg_match(); }
    },
    {
        "avg_no_match",
        [](const View& lhs, const View& rhs)
        { return lhs.avg_no_match() >= rhs.avg_no_match(); }
    }
};

static void consolidate_otn_states(OtnState* states)
{
    for ( unsigned i = 1; i < ThreadConfig::get_instance_max(); ++i )
        states[0] += states[i];
}

static std::vector<View> build_entries()
{
    assert(SnortConfig::get_conf());

    detection_option_tree_update_otn_stats(SnortConfig::get_conf()->detection_option_tree_hash_table);
    auto* otn_map = SnortConfig::get_conf()->otn_map;

    std::vector<View> entries;

    for ( auto* h = ghash_findfirst(otn_map); h; h = ghash_findnext(otn_map) )
    {
        auto* otn = static_cast<OptTreeNode*>(h->data);
        assert(otn);

        auto* states = otn->state;

        consolidate_otn_states(states);
        auto& state = states[0];

        if ( !state )
            continue;

        // FIXIT-L should we assert(otn->sigInfo)?
        entries.emplace_back(state, &otn->sigInfo);
    }

    return entries;
}

// FIXIT-L logic duplicated from ProfilerPrinter
static void print_single_entry(const View& v, unsigned n)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    std::ostringstream ss;

    {
        StatsTable table(fields, ss);

        table << StatsTable::ROW;

        table << n; // #

        table << v.sig_info.gid;
        table << v.sig_info.sid;
        table << v.sig_info.rev;

        table << v.checks();
        table << v.matches();
        table << v.alerts();

        table << clock_usecs(TO_USECS(v.elapsed()));
        table << clock_usecs(TO_USECS(v.avg_check()));
        table << clock_usecs(TO_USECS(v.avg_match()));
        table << clock_usecs(TO_USECS(v.avg_no_match()));

        table << v.timeouts();
        table << v.suspends();
    }

    LogMessage("%s", ss.str().c_str());
}

// FIXIT-L logic duplicated from ProfilerPrinter
static void print_entries(std::vector<View>& entries, ProfilerSorter<View>& sort, unsigned count)
{
    std::ostringstream ss;

    {
        StatsTable table(fields, ss);

        table << StatsTable::SEP;

        table << s_rule_table_title;
        if ( count )
            table << " (worst " << count;
        else
            table << " (all";

        if ( sort )
            table << ", sorted by " << sort.name;

        table << ")\n";

        table << StatsTable::HEADER;
    }

    LogMessage("%s", ss.str().c_str());

    if ( !count || count > entries.size() )
        count = entries.size();

    if ( sort )
        std::partial_sort(entries.begin(), entries.begin() + count, entries.end(), sort);

    for ( unsigned i = 0; i < count; ++i )
        print_single_entry(entries[i], i + 1);
}

}

void show_rule_profiler_stats(const RuleProfilerConfig& config)
{
    if ( !config.show )
        return;

    auto entries = rule_stats::build_entries();

    // if there aren't any eval'd rules, don't sort or print
    if ( entries.empty() )
        return;

    auto sort = rule_stats::sorters[config.sort];

    // FIXIT-L do we eventually want to be able print rule totals, too?
    print_entries(entries, sort, config.count);
}

void reset_rule_profiler_stats()
{
    assert(SnortConfig::get_conf());
    auto* otn_map = SnortConfig::get_conf()->otn_map;

    for ( auto* h = ghash_findfirst(otn_map); h; h = ghash_findnext(otn_map) )
    {
        auto* otn = static_cast<OptTreeNode*>(h->data);
        assert(otn);

        auto* rtn = getRtnFromOtn(otn);

        if ( !rtn || !is_network_protocol(rtn->snort_protocol_id) )
            continue;

        for ( unsigned i = 0; i < ThreadConfig::get_instance_max(); ++i )
        {
            auto& state = otn->state[i];
            state = OtnState();
        }
    }
}

void RuleContext::stop(bool match)
{
    if ( finished )
        return;

    finished = true;
    stats.update(sw.get(), match);
}

#ifdef UNIT_TEST

namespace
{
using RuleEntryVector = std::vector<rule_stats::View>;
using RuleStatsVector = std::vector<OtnState>;
} // anonymous namespace

static inline bool operator==(const RuleEntryVector& lhs, const RuleStatsVector& rhs)
{
    if ( lhs.size() != rhs.size() )
        return false;

    for ( unsigned i = 0; i < lhs.size(); ++i )
        if ( lhs[i].state != rhs[i] )
            return false;

    return true;
}

static inline OtnState make_otn_state(
    hr_duration elapsed, hr_duration elapsed_match,
    uint64_t checks, uint64_t matches)
{
    OtnState state;

    state.elapsed = elapsed;
    state.elapsed_match = elapsed_match;
    state.checks = checks;
    state.matches = matches;

    return state;
}

static inline rule_stats::View make_rule_entry(
    hr_duration elapsed, hr_duration elapsed_match,
    uint64_t checks, uint64_t matches)
{
    return {
        make_otn_state(elapsed, elapsed_match, checks, matches),
        nullptr
    };
}

static void avoid_optimization()
{ for ( int i = 0; i < 1024; ++i ); }

TEST_CASE( "otn state", "[profiler][rule_profiler]" )
{
    OtnState state_a;

    state_a.elapsed = 1_ticks;
    state_a.elapsed_match = 2_ticks;
    state_a.elapsed_no_match = 2_ticks;
    state_a.checks = 1;
    state_a.matches = 2;
    state_a.noalerts = 3;
    state_a.alerts = 4;

    SECTION( "incremental addition" )
    {
        OtnState state_b;

        state_b.elapsed = 4_ticks;
        state_b.elapsed_match = 5_ticks;
        state_b.elapsed_no_match = 6_ticks;
        state_b.checks = 5;
        state_b.matches = 6;
        state_b.noalerts = 7;
        state_b.alerts = 8;

        state_a += state_b;

        CHECK( (state_a.elapsed == 5_ticks) );
        CHECK( (state_a.elapsed_match == 7_ticks) );
        CHECK( (state_a.checks == 6) );
        CHECK( (state_a.matches == 8) );
        CHECK( (state_a.alerts == 12) );
    }

    SECTION( "reset" )
    {
        state_a = OtnState();

        CHECK( (state_a.elapsed == 0_ticks) );
        CHECK( (state_a.elapsed_match == 0_ticks) );
        CHECK( state_a.checks == 0 );
        CHECK( state_a.matches == 0 );
        CHECK( state_a.alerts == 0 );
    }

    SECTION( "bool()" )
    {
        CHECK( state_a );

        OtnState state_c = OtnState();
        CHECK_FALSE( state_c );

        state_c.elapsed = 1_ticks;
        CHECK( state_c );

        state_c.elapsed = 0_ticks;
        state_c.checks = 1;
        CHECK( state_c );
    }
}

TEST_CASE( "rule entry", "[profiler][rule_profiler]" )
{
    auto entry = make_rule_entry(3_ticks, 2_ticks, 3, 2);
    entry.state.alerts = 77;
    entry.state.latency_timeouts = 5;
    entry.state.latency_suspends = 2;

    SECTION( "copy assignment" )
    {
        auto copy = entry;
        CHECK( copy.sig_info.gid == entry.sig_info.gid );
        CHECK( copy.sig_info.sid == entry.sig_info.sid );
        CHECK( copy.sig_info.rev == entry.sig_info.rev );
        CHECK( copy.state == entry.state );
    }

    SECTION( "copy construction" )
    {
        rule_stats::View copy(entry);
        CHECK( copy.sig_info.gid == entry.sig_info.gid );
        CHECK( copy.sig_info.sid == entry.sig_info.sid );
        CHECK( copy.sig_info.rev == entry.sig_info.rev );
        CHECK( copy.state == entry.state );
    }

    SECTION( "elapsed" )
    {
        CHECK( (entry.elapsed() == 3_ticks) );
    }

    SECTION( "elapsed_match" )
    {
        CHECK( (entry.elapsed_match() == 2_ticks) );
    }

    SECTION( "elapsed_no_match" )
    {
        CHECK( (entry.elapsed_no_match() == 1_ticks) );
    }

    SECTION( "checks" )
    {
        CHECK( (entry.checks() == 3) );
    }

    SECTION( "matches" )
    {
        CHECK( (entry.matches() == 2) );
    }

    SECTION( "no_matches" )
    {
        CHECK( entry.no_matches() == 1 );
    }

    SECTION( "alerts" )
    {
        CHECK( (entry.alerts() == 77) );
    }

    SECTION( "timeouts" )
    {
        CHECK( (entry.timeouts() == 5) );
    }

    SECTION( "suspends" )
    {
        CHECK( (entry.suspends() == 2) );
    }


    SECTION( "avg_match" )
    {
        auto ticks = entry.avg_match();
        INFO( ticks.count() << " == " << (1_ticks).count() );
        CHECK( (ticks == 1_ticks) );
    }

    SECTION( "avg_no_match" )
    {
        auto ticks = entry.avg_no_match();
        INFO( ticks.count() << " == " << (1_ticks).count() );
        CHECK( (ticks == 1_ticks) );
    }

    SECTION( "avg_check" )
    {
        auto ticks = entry.avg_check();
        INFO( ticks.count() << " == " << (1_ticks).count() );
        CHECK( (ticks == 1_ticks) );
    }
}

TEST_CASE( "rule profiler sorting", "[profiler][rule_profiler]" )
{
    using Sort = RuleProfilerConfig::Sort;

    SECTION( "checks" )
    {
        RuleEntryVector entries {
            make_rule_entry(0_ticks, 0_ticks, 0, 0),
            make_rule_entry(0_ticks, 0_ticks, 1, 0),
            make_rule_entry(0_ticks, 0_ticks, 2, 0)
        };

        RuleStatsVector expected {
            make_otn_state(0_ticks, 0_ticks, 2, 0),
            make_otn_state(0_ticks, 0_ticks, 1, 0),
            make_otn_state(0_ticks, 0_ticks, 0, 0)
        };

        const auto& sorter = rule_stats::sorters[Sort::SORT_CHECKS];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);
        CHECK( entries == expected );
    }

    SECTION( "avg_check" )
    {
        RuleEntryVector entries {
            make_rule_entry(2_ticks, 0_ticks, 2, 0),
            make_rule_entry(8_ticks, 0_ticks, 4, 0),
            make_rule_entry(4_ticks, 0_ticks, 1, 0)
        };

        RuleStatsVector expected {
            make_otn_state(4_ticks, 0_ticks, 1, 0),
            make_otn_state(8_ticks, 0_ticks, 4, 0),
            make_otn_state(2_ticks, 0_ticks, 2, 0)
        };

        const auto& sorter = rule_stats::sorters[Sort::SORT_AVG_CHECK];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);
        CHECK( entries == expected );
    }

    SECTION( "total_time" )
    {
        RuleEntryVector entries {
            make_rule_entry(0_ticks, 0_ticks, 0, 0),
            make_rule_entry(1_ticks, 0_ticks, 0, 0),
            make_rule_entry(2_ticks, 0_ticks, 0, 0)
        };

        RuleStatsVector expected {
            make_otn_state(2_ticks, 0_ticks, 0, 0),
            make_otn_state(1_ticks, 0_ticks, 0, 0),
            make_otn_state(0_ticks, 0_ticks, 0, 0)
        };

        const auto& sorter = rule_stats::sorters[Sort::SORT_TOTAL_TIME];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);
        CHECK( entries == expected );
    }

    SECTION( "matches" )
    {
        RuleEntryVector entries {
            make_rule_entry(0_ticks, 0_ticks, 0, 0),
            make_rule_entry(0_ticks, 0_ticks, 0, 1),
            make_rule_entry(0_ticks, 0_ticks, 0, 2)
        };

        RuleStatsVector expected {
            make_otn_state(0_ticks, 0_ticks, 0, 2),
            make_otn_state(0_ticks, 0_ticks, 0, 1),
            make_otn_state(0_ticks, 0_ticks, 0, 0)
        };

        const auto& sorter = rule_stats::sorters[Sort::SORT_MATCHES];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);
        CHECK( entries == expected );
    }

    SECTION( "no matches" )
    {
        RuleEntryVector entries {
            make_rule_entry(0_ticks, 0_ticks, 4, 3),
            make_rule_entry(0_ticks, 0_ticks, 3, 1),
            make_rule_entry(0_ticks, 0_ticks, 4, 1)
        };

        RuleStatsVector expected {
            make_otn_state(0_ticks, 0_ticks, 4, 1),
            make_otn_state(0_ticks, 0_ticks, 3, 1),
            make_otn_state(0_ticks, 0_ticks, 4, 3)
        };

        const auto& sorter = rule_stats::sorters[Sort::SORT_NO_MATCHES];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);
        CHECK( entries == expected );
    }

    SECTION( "avg match" )
    {
        RuleEntryVector entries {
            make_rule_entry(4_ticks, 0_ticks, 0, 2),
            make_rule_entry(6_ticks, 0_ticks, 0, 2),
            make_rule_entry(8_ticks, 0_ticks, 0, 2)
        };

        RuleStatsVector expected {
            make_otn_state(8_ticks, 0_ticks, 0, 2),
            make_otn_state(6_ticks, 0_ticks, 0, 2),
            make_otn_state(4_ticks, 0_ticks, 0, 2)
        };

        const auto& sorter = rule_stats::sorters[Sort::SORT_AVG_MATCH];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);
        CHECK( entries == expected );
    }

    SECTION( "avg no match" )
    {
        RuleEntryVector entries {
            make_rule_entry(4_ticks, 0_ticks, 6, 2),
            make_rule_entry(6_ticks, 0_ticks, 5, 2),
            make_rule_entry(8_ticks, 0_ticks, 2, 0)
        };

        RuleStatsVector expected {
            make_otn_state(8_ticks, 0_ticks, 2, 0),
            make_otn_state(6_ticks, 0_ticks, 5, 2),
            make_otn_state(4_ticks, 0_ticks, 6, 2)
        };

        const auto& sorter = rule_stats::sorters[Sort::SORT_AVG_NO_MATCH];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);
        CHECK( entries == expected );
    }
}

TEST_CASE( "rule profiler time context", "[profiler][rule_profiler]" )
{
    dot_node_state_t stats;

    stats.elapsed = 0_ticks;
    stats.checks = 0;
    stats.elapsed_match = 0_ticks;

    SECTION( "automatically updates stats" )
    {
        {
            RuleContext ctx(stats);
            avoid_optimization();
        }

        INFO( "elapsed: " << stats.elapsed.count() );
        CHECK( (stats.elapsed > 0_ticks) );
        CHECK( stats.checks == 1 );
        INFO( "elapsed_match: " << stats.elapsed_match.count() );
        CHECK( (stats.elapsed_match == 0_ticks) );
    }

    SECTION( "explicitly calling stop" )
    {
        dot_node_state_t save;

        SECTION( "stop(true)" )
        {
            {
                RuleContext ctx(stats);
                avoid_optimization();
                ctx.stop(true);

                INFO( "elapsed: " << stats.elapsed.count() );
                CHECK( (stats.elapsed > 0_ticks) );
                CHECK( stats.checks == 1 );
                CHECK( stats.elapsed_match == stats.elapsed );
                save = stats;
            }
        }

        SECTION( "stop(false)" )
        {
            {
                RuleContext ctx(stats);
                avoid_optimization();
                ctx.stop(false);

                INFO( "elapsed: " << stats.elapsed.count() );
                CHECK( (stats.elapsed > 0_ticks) );
                CHECK( stats.checks == 1 );
                CHECK( (stats.elapsed_match == 0_ticks) );
                save = stats;
            }
        }

        INFO( "elapsed: " << stats.elapsed.count() );
        CHECK( stats.elapsed == save.elapsed );
        CHECK( stats.elapsed_match == save.elapsed_match );
        CHECK( stats.checks == save.checks );
    }
}

TEST_CASE( "rule pause", "[profiler][rule_profiler]" )
{
    dot_node_state_t stats;
    RuleContext ctx(stats);

    {
        RulePause pause(ctx);
        CHECK_FALSE( ctx.active() );
    }

    CHECK( ctx.active() );
}

#endif
