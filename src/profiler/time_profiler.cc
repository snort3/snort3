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

// time_profiler.cc author Joel Cornett <jocornet@cisco.com>

#include "time_profiler.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <chrono>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "log/messages.h"

#include "profiler_builder.h"
#include "profiler_nodes.h"
#include "profiler_stats_table.h"
#include "time_profiler_defs.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

#define s_time_table_title "Module Profile Statistics"

static const StatsTable::Field time_fields[] =
{
    { "#", 5, ' ', 0, std::ios_base::left },
    { "module", 24, ' ', 0, std::ios_base::fmtflags() },
    { "layer", 6, ' ', 0, std::ios_base::fmtflags() },
    { "checks", 7, ' ', 0, std::ios_base::fmtflags() },
    { "time (us)", 10, ' ', 0, std::ios_base::fmtflags() },
    { "avg/check", 11, ' ', 1, std::ios_base::fmtflags() },
    { "%/caller", 10, ' ', 2, std::ios_base::fmtflags() },
    { "%/total", 9, ' ', 2, std::ios_base::fmtflags() },
    { nullptr, 0, '\0', 0, std::ios_base::fmtflags() }
};

struct TimeEntry
{
    const ProfilerNode* node;
    std::string name;
    TimeProfilerStats stats;
    TimeProfilerStats caller_stats;
    std::vector<TimeEntry> entries;

    auto child_nodes() const -> const decltype(node->get_children())
    { return node->get_children(); }

    auto child_entries() -> decltype(entries)&
    { return entries; }

    hr_duration elapsed() const
    { return stats.elapsed; }

    uint64_t checks() const
    { return stats.checks; }

    hr_duration avg_check() const
    { return checks() ? hr_duration(elapsed().count() / checks()) : 0_ticks; }

    double pct_of(const TimeProfilerStats& o) const
    {
        if ( o.elapsed <= 0_ticks )
            return 0.0;

        return double(elapsed().count()) / double(o.elapsed.count()) * 100.0;
    }

    double pct_of(const TimeEntry& o) const
    { return pct_of(o.stats); }

    double pct_caller() const
    { return pct_of(caller_stats); }

    operator bool() const
    { return stats || !entries.empty(); }

    TimeEntry(const ProfilerNode& node, const ProfilerNode* parent = nullptr) :
        node(&node), name(node.name), stats(node.get_stats().time)
    {
        if ( parent )
            caller_stats = parent->get_stats().time;
    }
};

using TimeSort = TimeProfilerConfig::Sort;
using TimeBuilder = ProfilerBuilder<TimeEntry>;
using TimeIncludeFn = typename TimeBuilder::IncludeFn;
using TimeSortFn = typename TimeBuilder::SortFn;
using TimeBuilderConfig = typename TimeBuilder::Config;

static inline bool operator==(const TimeEntry& lhs, const TimeEntry& rhs)
{ return lhs.node == rhs.node; }

static bool s_time_include_fn(const ProfilerNode& node)
{ return node.get_stats().time; }

static bool get_time_sort_fn(TimeSort sort, TimeSortFn& sort_fn)
{
    switch ( sort )
    {
    case TimeSort::SORT_CHECKS:
        sort_fn = [](const TimeEntry& lhs, const TimeEntry& rhs)
        { return lhs.checks() >= rhs.checks(); };
        break;

    case TimeSort::SORT_AVG_CHECK:
        sort_fn = [](const TimeEntry& lhs, const TimeEntry& rhs)
        { return lhs.avg_check() >= rhs.avg_check(); };
        break;

    case TimeSort::SORT_TOTAL_TIME:
        sort_fn = [](const TimeEntry& lhs, const TimeEntry& rhs)
        { return lhs.elapsed() >= rhs.elapsed(); };
        break;

    default:
        return false;
        break;
    }

    return true;
}

static void print_single_entry(const TimeEntry& root, const TimeEntry& cur, int layer, int num)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    std::ostringstream ss;
    StatsTable table(time_fields, ss);

    table << StatsTable::ROW;

    if ( root == cur )
    {
        // if we're printing the root node
        table << "--";
        table << root.name;
        table << "--";
    }

    else
    {
        auto indent = std::string(layer, ' ') + std::to_string(num);
        table << indent; // num
        table << cur.name; // module
        table << layer; // layer
    }


    // checks
    table << cur.checks();

    // total time
    table << duration_cast<microseconds>(cur.elapsed()).count();

    // avg/check
    table << duration_cast<microseconds>(cur.avg_check()).count();

    if ( root == cur )
    {
        table << "--";
        table << "--";
    }

    else
    {
        table << cur.pct_caller(); // %/caller
        table << cur.pct_of(root); // %/total
    }

    table.finish();
    LogMessage("%s", ss.str().c_str());
}

static void print_children(const TimeEntry& root, const TimeEntry& cur, int layer, unsigned count)
{
    if ( !count || count > cur.entries.size() )
        count = cur.entries.size();

    for ( unsigned i = 0; i < count; ++i )
    {
        print_single_entry(root, cur.entries[i], layer + 1, i + 1);
        print_children(root, cur.entries[i], layer + 1, count);
    }
}

static void print_entries(TimeEntry& root, unsigned count)
{
    std::ostringstream ss;
    StatsTable table(time_fields, ss);

    table << StatsTable::SEP;

    table << s_time_table_title;
    if ( count )
        table << " (worst " << count << ")\n";
    else
        table << " (all)\n";

    table << StatsTable::HEADER;
    table.finish();

    LogMessage("%s", ss.str().c_str());

    print_children(root, root, 0, count);
    print_single_entry(root, root, 0, 0);
}

void show_time_profiler_stats(ProfilerTree& nodes, const TimeProfilerConfig& config)
{
    if ( !config.show )
        return;

    TimeIncludeFn include_fn(s_time_include_fn);
    TimeSortFn sort_fn;

    TimeBuilderConfig builder_config;
    builder_config.include_fn = &include_fn;
    builder_config.sort_fn = get_time_sort_fn(config.sort, sort_fn) ? &sort_fn : nullptr;
    builder_config.max_entries = config.count;

    TimeBuilder builder(builder_config);

    TimeEntry root(nodes.get_root());

    builder.build(root);

    if ( root.entries.empty() && !root.stats )
        return;

    print_entries(root, config.count);
}

#ifdef UNIT_TEST

namespace
{
using TimeEntryVector = std::vector<TimeEntry>;
using TimeStatsVector = std::vector<TimeProfilerStats>;
} // anonymous namespace

static inline bool operator==(const TimeEntryVector& lhs, const TimeStatsVector& rhs)
{
    if ( lhs.size() != rhs.size() )
        return false;

    for ( unsigned i = 0; i < lhs.size(); ++i )
        if ( lhs[i].stats != rhs[i] )
            return false;

    return true;
}

static inline std::ostream& operator<<(std::ostream& os, const TimeProfilerStats& o)
{
    os << "{" << o.elapsed.count() << ", " << o.checks << "}";
    return os;
}

static inline TimeEntry make_time_entry(hr_duration elapsed, uint64_t checks)
{
    ProfilerNode node("");
    TimeEntry entry(node);
    entry.stats = { elapsed, checks };
    entry.node = nullptr;
    return entry;
}

TEST_CASE( "time profiler stats", "[profiler][time_profiler]" )
{
    TimeProfilerStats stats = { 2_ticks, 3 };

    SECTION( "equality" )
    {
        auto stats_b = stats;

        CHECK( stats == stats_b );
        CHECK( stats != TimeProfilerStats() );
    }

    SECTION( "operator+=" )
    {
        TimeProfilerStats stats_b = { 1_ticks, 1 };
        stats += stats_b;

        CHECK( stats.elapsed == 3_ticks );
        CHECK( stats.checks == 4 );
    }

    SECTION( "update" )
    {
        stats.update(1_ticks);

        CHECK( stats.elapsed == 3_ticks );
        CHECK( stats.checks == 4 );
    }

    SECTION( "reset" )
    {
        stats.reset();

        CHECK( stats == TimeProfilerStats() );
    }

    SECTION( "bool()" )
    {
        CHECK( stats );
        CHECK_FALSE( TimeProfilerStats() );
    }
}

TEST_CASE( "time profiler entry", "[profiler][time_profiler]" )
{
    ProfileStats the_stats = { { 12_ticks, 6 } };
    ProfilerNode node("foo");
    node.set_stats(the_stats);

    TimeEntry entry(node);

    SECTION( "constructor sets members" )
    {
        CHECK( entry.name == "foo" );
        CHECK( entry.node == &node );
        CHECK( entry.entries.empty() );
        CHECK( entry.stats == the_stats );
        CHECK_FALSE( entry.caller_stats );
    }

    SECTION( "operator bool()" )
    {
        REQUIRE( entry.child_entries().empty() );
        REQUIRE( entry.stats );

        CHECK( entry );

        entry.stats.reset();
        CHECK_FALSE( entry );

        entry.child_entries().push_back(entry);
        CHECK( entry );
    }

    SECTION( "elapsed" )
    {
        CHECK( entry.elapsed() == 12_ticks );
    }

    SECTION( "checks" )
    {
        CHECK( entry.checks() == 6 );
    }

    SECTION( "avg_check" )
    {
        CHECK( entry.avg_check() == 2_ticks );
    }

    SECTION( "pct_of" )
    {
        TimeProfilerStats tps = { 24_ticks, 0 };
        CHECK( entry.pct_of(tps) == 50.0 );
        CHECK( entry.pct_of(entry) == 100.0 );

        SECTION( "pct_caller" )
        {
            entry.caller_stats = tps;
            CHECK( entry.pct_caller() == 50.0 );
        }
    }
}

TEST_CASE( "time profiler sorting", "[profiler][time_profiler]" )
{
    using Sort = TimeProfilerConfig::Sort;

    TimeSortFn sort_fn;

    SECTION( "checks" )
    {
        TimeEntryVector entries {
            make_time_entry(0_ticks, 0),
            make_time_entry(0_ticks, 10),
            make_time_entry(1_ticks, 5)
        };

        TimeStatsVector expected {
            { 0_ticks, 10 },
            { 1_ticks, 5 },
            { 0_ticks, 0 }
        };

        REQUIRE( get_time_sort_fn(Sort::SORT_CHECKS, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);

        CHECK( entries == expected );
    }

    SECTION( "avg_check" )
    {
        TimeEntryVector entries {
            make_time_entry(0_ticks, 0),
            make_time_entry(10_ticks, 10),
            make_time_entry(10_ticks, 5)
        };

        TimeStatsVector expected {
            { 10_ticks, 5 },
            { 10_ticks, 10 },
            { 0_ticks, 0 }
        };

        REQUIRE( get_time_sort_fn(Sort::SORT_AVG_CHECK, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);

        CHECK( entries == expected );
    }

    SECTION( "total_time" )
    {
        TimeEntryVector entries {
            make_time_entry(0_ticks, 0),
            make_time_entry(10_ticks, 10),
            make_time_entry(11_ticks, 5)
        };

        TimeStatsVector expected {
            { 11_ticks, 5 },
            { 10_ticks, 10 },
            { 0_ticks, 0 }
        };

        REQUIRE( get_time_sort_fn(Sort::SORT_TOTAL_TIME, sort_fn) );
        std::stable_sort(entries.begin(), entries.end(), sort_fn);

        CHECK( entries == expected );
    }
}

TEST_CASE( "build entries", "[profiler][time_profiler]" )
{
    // Tree should look like
    //
    //  A -- B -- D
    //     |
    //     - C -- E
    //          |
    //          - F
    //

    ProfileStats stats;
    stats.time = { 1_ticks, 1 }; // make non-zero
    REQUIRE( stats.time );

    // Construct the node tree
    ProfilerNode a("a"), b("b"), c("c"), d("d"), e("e"), f("f");
    a.add_child(&b); a.add_child(&c);
    b.add_child(&d);
    c.add_child(&e); c.add_child(&f);

    // Set the stats for each node
    a.set_stats(stats);
    b.set_stats(stats);
    c.set_stats(stats);
    d.set_stats(stats);
    e.set_stats(stats);
    f.set_stats(stats);

    TimeEntry root(a);

    TimeIncludeFn include_fn = s_time_include_fn;
    TimeBuilderConfig builder_config;
    builder_config.include_fn = &include_fn;
    TimeBuilder builder(builder_config);

    builder.build(root);

    CHECK( root.name == "a" );
    CHECK( root.entries.size() == 2 );

    for ( const auto& child_L1 : root.entries )
    {
        if ( child_L1.name == "b" )
        {
            REQUIRE( child_L1.entries.size() == 1 );
            auto& child_L2 = child_L1.entries[0];
            CHECK( child_L2.name == "d" );
            CHECK( child_L2.entries.size() == 0 );
        }

        else if ( child_L1.name == "c" )
        {
            CHECK( child_L1.entries.size() == 2 );
            for ( const auto& child_L2 : child_L1.entries )
            {
                if ( child_L2.name == "e" )
                    CHECK( child_L2.entries.size() == 0 );

                else if ( child_L2.name == "f" )
                    CHECK( child_L2.entries.size() == 0 );

                else
                    FAIL(
                        "expected 'e' or 'f' node, instead got '" <<
                        child_L1.name << "'"
                    );

            }
        }

        else
            FAIL(
                "expected 'b' or 'c' node, instead got '" <<
                child_L1.name << "'"
            );
    }
}

TEST_CASE( "time profiler time context base", "[profiler][time_profiler]" )
{
    TimeContextBase ctx;

    SECTION( "start called on instantiation" )
    {
        CHECK( ctx.active() );
    }

    SECTION( "time can be started and paused and restarted" )
    {
        REQUIRE( ctx.active() );

        ctx.pause();
        CHECK_FALSE( ctx.active() );

        ctx.start();
        CHECK( ctx.active() );
    }
}

TEST_CASE( "time profiler time context", "[profiler][time_profiler]" )
{
    TimeProfilerStats stats;
    REQUIRE_FALSE( stats );

    SECTION( "automatically updates stats" )
    {
        {
            TimeContext ctx(stats);
        }

        CHECK( stats.elapsed > 0_ticks );
        CHECK( stats.checks == 1 );
    }

    SECTION( "explicitly calling stop updates stats ONCE" )
    {
        TimeProfilerStats save;

        {
            TimeContext ctx(stats);
            ctx.stop();

            CHECK( stats.elapsed > 0_ticks );
            CHECK( stats.checks == 1 );
            save = stats;
        }

        CHECK( stats == save );
    }
}

TEST_CASE( "time context pause", "[profiler][time_profiler]" )
{
    TimeContextBase ctx;

    {
        TimePause pause(ctx);
        CHECK_FALSE( ctx.active() );
    }

    CHECK( ctx.active() );
}

#endif
