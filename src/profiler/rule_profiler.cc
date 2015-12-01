//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "rule_profiler.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <functional>
#include <iostream>
#include <sstream>
#include <vector>

#include "detection/detection_options.h"
#include "detection/treenodes.h"
#include "hash/sfghash.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "target_based/snort_protocols.h"

#include "profiler_stats_table.h"
#include "rule_profiler_defs.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

#define s_rule_table_title "Rule Profile Statistics"

static const StatsTable::Field rule_fields[] =
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
#ifdef PPM_MGR
    { "disables", 9, '\0', 0, std::ios_base::fmtflags() },
#endif
    { nullptr, 0, '\0', 0, std::ios_base::fmtflags() }
};

struct RuleEntry
{
    OtnState state;
    const SigInfo* sig_info;

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

#ifdef PPM_MGR
    uint64_t ppm_disable_count() const
    { return state.ppm_disable_cnt; }
#endif

    hr_duration time_per(hr_duration d, uint64_t v) const
    {
        if ( v  == 0 )
            return 0_ticks;

        return hr_duration(d.count() / v);
    }

    hr_duration avg_match() const
    { return time_per(elapsed_match(), matches()); }

    hr_duration avg_no_match() const
    { return time_per(elapsed_no_match(), no_matches()); }

    hr_duration avg_check() const
    { return time_per(elapsed(), checks()); }

    RuleEntry(const OtnState& otn_state, const SigInfo* si = nullptr) :
        state(otn_state), sig_info(si) { }
};

using RuleEntrySortFn = std::function<bool(const RuleEntry&, const RuleEntry&)>;

static inline OtnState& operator+=(OtnState& lhs, const OtnState& rhs)
{
    lhs.elapsed += rhs.elapsed;
    lhs.elapsed_match += rhs.elapsed_match;
    lhs.checks += rhs.checks;
    lhs.matches += rhs.matches;
    lhs.alerts += rhs.alerts;
    return lhs;
}

static bool get_rule_sort_fn(RuleProfilerConfig::Sort sort, RuleEntrySortFn& fn)
{
    using Sort = RuleProfilerConfig::Sort;

    switch ( sort )
    {
        case Sort::SORT_CHECKS:
            fn = [](const RuleEntry& lhs, const RuleEntry& rhs)
            { return lhs.checks() >= rhs.checks(); };
            break;

        case Sort::SORT_AVG_CHECK:
            fn = [](const RuleEntry& lhs, const RuleEntry& rhs)
            { return lhs.avg_check() >= rhs.avg_check(); };
            break;

        case Sort::SORT_TOTAL_TIME:
            fn = [](const RuleEntry& lhs, const RuleEntry& rhs)
            { return lhs.elapsed() >= rhs.elapsed(); };
            break;

        case Sort::SORT_MATCHES:
            fn = [](const RuleEntry& lhs, const RuleEntry& rhs)
            { return lhs.matches() >= rhs.matches(); };
            break;

        case Sort::SORT_NO_MATCHES:
            fn = [](const RuleEntry& lhs, const RuleEntry& rhs)
            { return lhs.no_matches() >= rhs.no_matches(); };
            break;

        case Sort::SORT_AVG_MATCH:
            fn = [](const RuleEntry& lhs, const RuleEntry& rhs)
            { return lhs.avg_match() >= rhs.avg_match(); };
            break;

        case Sort::SORT_AVG_NO_MATCH:
            fn = [](const RuleEntry& lhs, const RuleEntry& rhs)
            { return lhs.avg_no_match() >= rhs.avg_no_match(); };
            break;

        default:
            return false;
            break;
    }

    return true;
}

static void consolidate_otn_states(OtnState* states)
{
    for ( unsigned i = 1; i < get_instance_max(); ++i )
        states[0] += states[i];
}

static void build_entries(std::vector<RuleEntry>& entries)
{
    assert(snort_conf);

    detection_option_tree_update_otn_stats(snort_conf->detection_option_tree_hash_table);
    auto* otn_map = snort_conf->otn_map;

    for ( auto* h = sfghash_findfirst(otn_map); h; h = sfghash_findnext(otn_map) )
    {
        auto* otn = static_cast<OptTreeNode*>(h->data);
        assert(otn);

        auto* states = otn->state;

        consolidate_otn_states(states);
        auto& state = states[0];

        if ( !state )
            continue;

        entries.emplace_back(state, &otn->sigInfo);
    }
}

static void print_single_entry(const RuleEntry& entry, unsigned n)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    std::ostringstream ss;
    StatsTable table(rule_fields, ss);

    table << StatsTable::ROW;

    table << n; // #

    // FIXIT-L J these should be guaranteed to be non-null
    table << (entry.sig_info ? entry.sig_info->generator : 0); // gid
    table << (entry.sig_info ? entry.sig_info->id : 0); // sid
    table << (entry.sig_info ? entry.sig_info->rev : 0); // rev

    table << entry.checks(); // checks
    table << entry.matches(); // matches
    table << entry.alerts(); // alerts

    table << duration_cast<microseconds>(entry.elapsed()).count(); // time
    table << duration_cast<microseconds>(entry.avg_check()).count(); // avg/check
    table << duration_cast<microseconds>(entry.avg_match()).count(); // avg/match
    table << duration_cast<microseconds>(entry.avg_no_match()).count(); // avg/non-match

#ifdef PPM_MGR
    table << entry.ppm_disable_count(); // disables
#endif

    table.finish();
    LogMessage("%s", ss.str().c_str());
}

static void print_entries(std::vector<RuleEntry>& entries, unsigned count)
{
    std::ostringstream ss;
    StatsTable table(rule_fields, ss);

    table << StatsTable::SEP;

    table << s_rule_table_title;
    if ( count )
        table << " (worst " << count << ")\n";
    else
        table << " (all)\n";

    table << StatsTable::HEADER;
    table.finish();

    LogMessage("%s", ss.str().c_str());

    if ( !count || count > entries.size() )
        count = entries.size();

    for ( unsigned i = 0; i < count; ++i )
        print_single_entry(entries[i], i + 1);
}

void show_rule_profiler_stats(const RuleProfilerConfig& config)
{
    if ( !config.show )
        return;

    std::vector<RuleEntry> entries;
    build_entries(entries);

    // if there aren't any eval'd rules, don't sort or print
    if ( entries.empty() )
        return;

    RuleEntrySortFn sort_fn;
    if ( get_rule_sort_fn(config.sort, sort_fn) )
    {
        auto stop = ( !config.count || config.count >= entries.size() ) ?
            entries.end() :
            entries.begin() + config.count;

        std::partial_sort(entries.begin(), stop, entries.end(), sort_fn);
    }

    print_entries(entries, config.count);
}

void reset_rule_profiler_stats()
{
    assert(snort_conf);
    auto* otn_map = snort_conf->otn_map;

    for ( auto* h = sfghash_findfirst(otn_map); h; h = sfghash_findnext(otn_map) )
    {
        auto* otn = static_cast<OptTreeNode*>(h->data);
        assert(otn);

        auto* rtn = getRtnFromOtn(otn);

        if ( !rtn || !is_network_protocol(rtn->proto) )
            continue;

        for ( unsigned i = 0; i < get_instance_max(); ++i )
        {
            auto& state = otn->state[i];
            state.reset();
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
using RuleEntryVector = std::vector<RuleEntry>;
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
    return {
        elapsed,
        elapsed_match,
        0_ticks,

        checks,
        matches,
        0,
        0,
        0,
        0
    };
}

static inline RuleEntry make_rule_entry(
    hr_duration elapsed, hr_duration elapsed_match,
    uint64_t checks, uint64_t matches)
{
    return {
        make_otn_state(elapsed, elapsed_match, checks, matches),
        nullptr
    };
}

TEST_CASE( "otn state", "[profiler][rule_profiler]" )
{
    OtnState state_a = { 1_ticks, 2_ticks, 3_ticks, 1, 2, 3, 4, 0, 0};

    SECTION( "incremental addition" )
    {
        OtnState state_b = { 4_ticks, 5_ticks, 6_ticks, 5, 6, 7, 8, 0, 0};

        state_a += state_b;

        CHECK( state_a.elapsed == 5_ticks );
        CHECK( state_a.elapsed_match == 7_ticks );
        CHECK( state_a.checks == 6 );
        CHECK( state_a.matches == 8 );
        CHECK( state_a.alerts == 12 );
    }

    SECTION( "reset" )
    {
        state_a.reset();
        CHECK( state_a.elapsed == 0_ticks );
        CHECK( state_a.elapsed_match == 0_ticks );
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
    SigInfo sig_info;
    auto entry = make_rule_entry(3_ticks, 2_ticks, 3, 2);
    entry.state.alerts = 77;
#ifdef PPM_MGR
    entry.state.ppm_disable_cnt = 5;
#endif

    SECTION( "copy assignment" )
    {
        auto copy = entry;
        CHECK( copy.sig_info == entry.sig_info );
        CHECK( copy.state == entry.state );
    }

    SECTION( "copy construction" )
    {
        RuleEntry copy(entry);
        CHECK( copy.sig_info == entry.sig_info );
        CHECK( copy.state == entry.state );
    }

    SECTION( "elapsed" )
    {
        CHECK( entry.elapsed() == 3_ticks );
    }

    SECTION( "elapsed_match" )
    {
        CHECK( entry.elapsed_match() == 2_ticks );
    }

    SECTION( "elapsed_no_match" )
    {
        CHECK( entry.elapsed_no_match() == 1_ticks );
    }

    SECTION( "checks" )
    {
        CHECK( entry.checks() == 3 );
    }

    SECTION( "matches" )
    {
        CHECK( entry.matches() == 2 );
    }

    SECTION( "no_matches" )
    {
        CHECK( entry.no_matches() == 1 );
    }

    SECTION( "alerts" )
    {
        CHECK( entry.alerts() == 77 );
    }

#ifdef PPM_MGR
    SECTION( "ppm_disable_count" )
    {
        CHECK( entry.ppm_disable_count() == 5 );
    }
#endif

    SECTION( "avg_match" )
    {
        auto ticks = entry.avg_match();
        INFO( ticks.count() << " == " << (1_ticks).count() );
        CHECK( ticks == 1_ticks );
    }

    SECTION( "avg_no_match" )
    {
        auto ticks = entry.avg_no_match();
        INFO( ticks.count() << " == " << (1_ticks).count() );
        CHECK( ticks == 1_ticks );
    }

    SECTION( "avg_check" )
    {
        auto ticks = entry.avg_check();
        INFO( ticks.count() << " == " << (1_ticks).count() );
        CHECK( ticks == 1_ticks );
    }
}

TEST_CASE( "rule profiler sorting", "[profiler][rule_profiler]" )
{
    using Sort = RuleProfilerConfig::Sort;
    RuleEntrySortFn sort_fn;

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

        REQUIRE( get_rule_sort_fn(Sort::SORT_CHECKS, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);
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

        REQUIRE( get_rule_sort_fn(Sort::SORT_AVG_CHECK, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);
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

        REQUIRE( get_rule_sort_fn(Sort::SORT_TOTAL_TIME, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);
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

        REQUIRE( get_rule_sort_fn(Sort::SORT_MATCHES, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);
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

        REQUIRE( get_rule_sort_fn(Sort::SORT_NO_MATCHES, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);
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

        REQUIRE( get_rule_sort_fn(Sort::SORT_AVG_MATCH, sort_fn) );
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

        REQUIRE( get_rule_sort_fn(Sort::SORT_AVG_NO_MATCH, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);
        CHECK( entries == expected );
    }
}

TEST_CASE( "rule profiler time context", "[profiler][rule_profiler]" )
{
    dot_node_state_t stats;
    memset(&stats, 0, sizeof(stats));

    SECTION( "automatically updates stats" )
    {
        {
            RuleContext ctx(stats);
        }

        CHECK( stats.elapsed > 0_ticks );
        CHECK( stats.checks == 1 );
        CHECK( stats.elapsed_match == 0_ticks );
    }

    SECTION( "explicitly calling stop" )
    {
        dot_node_state_t save;

        SECTION( "stop(true)" )
        {
            {
                RuleContext ctx(stats);
                ctx.stop(true);

                CHECK( stats.elapsed > 0_ticks );
                CHECK( stats.checks == 1 );
                CHECK( stats.elapsed_match == stats.elapsed );
                save = stats;
            }
        }

        SECTION( "stop(false)" )
        {
            {
                RuleContext ctx(stats);
                ctx.stop(false);

                CHECK( stats.elapsed > 0_ticks );
                CHECK( stats.checks == 1 );
                CHECK( stats.elapsed_match == 0_ticks );
                save = stats;
            }
        }

        CHECK( stats.elapsed == save.elapsed );
        CHECK( stats.elapsed_match == save.elapsed_match );
        CHECK( stats.checks == save.checks );
    }
}


#endif
