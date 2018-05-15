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

// time_profiler.cc author Joel Cornett <jocornet@cisco.com>

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "time_profiler.h"

#include "profiler_nodes.h"
#include "profiler_tree_builder.h"
#include "profiler_printer.h"
#include "profiler_stats_table.h"
#include "time_profiler_defs.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

#define s_time_table_title "module profile"

namespace time_stats
{

static const StatsTable::Field fields[] =
{
    { "#", 5, ' ', 0, std::ios_base::left },
    { "module", 24, ' ', 0, std::ios_base::fmtflags() },
    { "layer", 6, ' ', 0, std::ios_base::fmtflags() },
    { "checks", 10, ' ', 0, std::ios_base::fmtflags() },
    { "time(us)", 11, ' ', 0, std::ios_base::fmtflags() },
    { "avg/check", 11, ' ', 1, std::ios_base::fmtflags() },
    { "%/caller", 10, ' ', 2, std::ios_base::fmtflags() },
    { "%/total", 9, ' ', 2, std::ios_base::fmtflags() },
    { nullptr, 0, '\0', 0, std::ios_base::fmtflags() }
};

struct View
{
    std::string name;
    TimeProfilerStats stats;
    TimeProfilerStats caller_stats;

    hr_duration elapsed() const
    { return stats.elapsed; }

    uint64_t checks() const
    { return stats.checks; }

    hr_duration avg_check() const
    { return checks() ? hr_duration(TO_TICKS(elapsed()) / checks()) : 0_ticks; }

    double pct_of(const TimeProfilerStats& o) const
    {
        if ( o.elapsed <= 0_ticks )
            return 0.0;

        return double(TO_TICKS(elapsed())) / double(TO_TICKS(o.elapsed)) * 100.0;
    }

    double pct_caller() const
    { return pct_of(caller_stats); }

    bool operator==(const View& rhs) const
    { return name == rhs.name; }

    bool operator!=(const View& rhs) const
    { return !(*this == rhs); }

    const TimeProfilerStats& get_stats() const
    { return stats; }

    View(const ProfilerNode& node, const View* parent = nullptr) :
        name(node.name), stats(node.get_stats().time)
    {
        if ( parent )
            caller_stats = parent->stats;
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
        { return lhs.elapsed() >= rhs.elapsed(); }
    }
};

static bool include_fn(const ProfilerNode& node)
{ return node.get_stats().time; }

static void print_fn(StatsTable& t, const View& v)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    // checks
    t << v.checks();

    // total time
    t << clock_usecs(TO_USECS(v.elapsed()));

    // avg/check
    t << clock_usecs(TO_USECS(v.avg_check()));
}

} // namespace time_stats

void show_time_profiler_stats(ProfilerNodeMap& nodes, const TimeProfilerConfig& config)
{
    if ( !config.show )
        return;

    ProfilerBuilder<time_stats::View> builder(time_stats::include_fn);
    auto root = builder.build(nodes.get_root());

    if ( root.children.empty() && !root.view.stats )
        return;

    const auto& sorter = time_stats::sorters[config.sort];

    ProfilerPrinter<time_stats::View> printer(time_stats::fields, time_stats::print_fn, sorter);
    printer.print_table(s_time_table_title, root, config.count, config.max_depth);
}

#ifdef UNIT_TEST

namespace
{

using TimeEntry = ProfilerBuilder<time_stats::View>::Entry;
using TimeEntryVector = std::vector<TimeEntry>;
using TimeStatsVector = std::vector<TimeProfilerStats>;
using TimeSorter = ProfilerSorter<time_stats::View>;

struct TestView
{
    std::string name;

    bool operator==(const TestView& rhs) const
    { return name == rhs.name; }

    TestView(const ProfilerNode& node, const TestView*) :
        name(node.name) { }
};

} // anonymous namespace

static inline bool operator==(const TimeEntryVector& lhs, const TimeStatsVector& rhs)
{
    if ( lhs.size() != rhs.size() )
        return false;

    for ( unsigned i = 0; i < lhs.size(); ++i )
        if ( lhs[i].view.stats != rhs[i] )
            return false;

    return true;
}

static inline TimeEntry make_time_entry(hr_duration elapsed, uint64_t checks)
{
    ProfilerNode node("");
    TimeEntry entry(node);
    entry.view.stats = { elapsed, checks };
    return entry;
}

static void avoid_optimization()
{ for ( int i = 0; i < 1024; ++i ) ; }

TEST_CASE( "profiler tree builder", "[profiler][profiler_tree_builder]" )
{
    using Builder = ProfilerBuilder<TestView>;
    using Entry = Builder::Entry;

    SECTION( "profiler tree builder entry" )
    {
        ProfilerNode node("foo");
        Entry entry(node);

        SECTION( "==/!=" )
        {
            CHECK( entry == entry );
            CHECK_FALSE( entry != entry );

            ProfilerNode other_node("bar");
            Entry other_entry(other_node);

            CHECK_FALSE( entry == other_entry );
        }
    }

    SECTION( "builds tree" )
    {
        // Tree should look like this:
        //
        //  A -- B -- D
        //     |
        //     - C -- E
        //          |
        //          - F
        //

        // Construct the node tree
        ProfilerNode a("a"), b("b"), c("c"), d("d"), e("e"), f("f");
        a.add_child(&b); a.add_child(&c);
        b.add_child(&d);
        c.add_child(&e); c.add_child(&f);

        SECTION( "base" )
        {
            Builder builder([](const ProfilerNode&) { return true; });
            auto root = builder.build(a);

            CHECK( root.view.name == "a" );

            REQUIRE( (root.children.size() == 2) );

            SECTION( "b branch" )
            {
                auto& b_entry = root.children[0];

                REQUIRE( b_entry.view.name == "b" );
                REQUIRE( b_entry.children.size() == 1 );

                auto& d_entry = b_entry.children.back();
                CHECK( d_entry.view.name == "d" );
            }

            SECTION( "c branch" )
            {
                auto &c_entry = root.children[1];

                REQUIRE( c_entry.view.name == "c" );
                REQUIRE( (c_entry.children.size() == 2) );

                CHECK( c_entry.children[0].view.name == "e" );
                CHECK( c_entry.children[1].view.name == "f" );
            }
        }

        SECTION( "filter included nodes" )
        {
            // exclude the "c" branch of the tree
            Builder builder([](const ProfilerNode& n) { return n.name != "c"; });
            auto root = builder.build(a);

            REQUIRE( root.children.size() == 1 );

            auto& b_entry = root.children.back();
            REQUIRE( b_entry.children.size() == 1 );
            CHECK( b_entry.children[0].view.name == "d" );
        }
    }
}

TEST_CASE( "profiler printer", "[profiler][profiler_printer]" )
{
    // FIXIT-L currently, we are using LogMessage as ProfilerPrinter output, this makes
    // unit-testing output infeasible
    // CHECK( false );
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

        CHECK( (stats.elapsed == 3_ticks) );
        CHECK( (stats.checks == 4) );
    }

    SECTION( "update" )
    {
        stats.update(1_ticks);

        CHECK( (stats.elapsed == 3_ticks) );
        CHECK( (stats.checks == 4) );
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

TEST_CASE( "time profiler view", "[profiler][time_profiler]" )
{
    ProfileStats the_stats;
    ProfilerNode node("foo");

    the_stats.time = { 12_ticks, 6 };
    node.set_stats(the_stats);

    SECTION( "no parent" )
    {
        time_stats::View view(node);

        SECTION( "ctor sets members" )
        {
            CHECK( view.name == "foo" );
            CHECK( view.stats == the_stats.time );
            CHECK_FALSE( view.caller_stats );
        }

        SECTION( "elapsed" )
        {
            CHECK( (view.elapsed() == 12_ticks) );
        }

        SECTION( "checks" )
        {
            CHECK( (view.checks() == 6) );
        }

        SECTION( "avg_check" )
        {
            CHECK( (view.avg_check() == 2_ticks) );
        }

        SECTION( "pct_of" )
        {
            TimeProfilerStats tps = { 24_ticks, 6 };
            CHECK( (view.pct_of(tps) == 50.0) );

            SECTION( "zero division" )
            {
                tps.elapsed = 0_ticks;
                CHECK( (view.pct_of(tps) == 0.0) );
            }
        }
    }

    SECTION( "parent set" )
    {
        time_stats::View parent(node);
        parent.stats = { 24_ticks, 6 };

        time_stats::View child(node, &parent);
        CHECK( child.caller_stats );

        SECTION( "pct_caller" )
        {
            CHECK( (child.pct_caller() == 50.0) );
        }
    }
}

TEST_CASE( "time profiler sorting", "[profiler][time_profiler]" )
{
    using Sort = TimeProfilerConfig::Sort;

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

        const auto& sorter = time_stats::sorters[Sort::SORT_CHECKS];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);

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

        const auto& sorter = time_stats::sorters[Sort::SORT_AVG_CHECK];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);

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

        const auto& sorter = time_stats::sorters[Sort::SORT_TOTAL_TIME];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);

        CHECK( entries == expected );
    }
}

TEST_CASE( "time profiler time context", "[profiler][time_profiler]" )
{
    TimeProfilerStats stats;
    REQUIRE_FALSE( stats );

    SECTION( "lifetime" )
    {
        {
            TimeContext ctx(stats);
            CHECK( ctx.active() );
            CHECK( stats.ref_count == 1 );
        }

        CHECK( stats.ref_count == 0 );
    }

    SECTION( "manually managed lifetime" )
    {
        {
            TimeContext ctx(stats);
            CHECK( ctx.active() );
            CHECK( stats.ref_count == 1 );
            ctx.stop();
            CHECK_FALSE( ctx.active() );
            CHECK( stats.ref_count == 0 );
        }

        CHECK( stats.ref_count == 0 );
    }

    SECTION( "updates stats" )
    {
        TimeContext ctx(stats);
        avoid_optimization();
        ctx.stop();

        CHECK( stats );
    }

    SECTION( "reentrance" )
    {
        {
            TimeContext ctx1(stats);

            CHECK( stats.ref_count == 1 );

            {
                TimeContext ctx2(stats);

                CHECK( (stats.ref_count == 2) );
            }

            CHECK( stats.ref_count == 1 );
        }

        CHECK( stats.ref_count == 0 ); // ref_count restored
        CHECK( stats.checks == 1 ); // only updated once
    }
}

TEST_CASE( "time context exclude", "[profiler][time_profiler]" )
{
    // NOTE: this test *may* fail if the time it takes to execute the exclude context is 0_ticks (unlikely)
    TimeProfilerStats stats = { hr_duration::max(), 0 };

    {
        TimeExclude exclude(stats);
        avoid_optimization();
    }

    CHECK( stats.elapsed < hr_duration::max() );
}

#endif
