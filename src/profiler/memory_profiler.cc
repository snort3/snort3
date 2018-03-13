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

// memory_profiler.cc author Joel Cornett <jocornet@cisco.com>

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "memory_profiler.h"

#include "profiler_nodes.h"
#include "profiler_printer.h"
#include "memory_defs.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// -----------------------------------------------------------------------------
// show statistics
// -----------------------------------------------------------------------------

#define s_memory_table_title "memory profile"

namespace memory_stats
{

static const StatsTable::Field fields[] =
{
    { "#", 5, ' ', 0, std::ios_base::left },
    { "module", 20, ' ', 0, std::ios_base::fmtflags() },
    { "layer", 6, ' ', 0, std::ios_base::fmtflags() },
    { "allocs", 7, ' ', 0, std::ios_base::fmtflags() },
    { "used (kb)", 12, ' ', 2, std::ios_base::fmtflags() },
    { "avg/allocation", 15, ' ', 1, std::ios_base::fmtflags() },
    { "%/caller", 10, ' ', 2, std::ios_base::fmtflags() },
    { "%/total", 9, ' ', 2, std::ios_base::fmtflags() },
    { nullptr, 0, '\0', 0, std::ios_base::fmtflags() }
};

struct View
{
    std::string name;
    std::shared_ptr<MemoryStats> stats;
    MemoryStats* caller_stats = nullptr;

    uint64_t allocs() const
    { return stats->allocs; }

    uint64_t total() const
    { return stats->allocated; }

    double avg_alloc() const
    {
        if ( !stats->allocs )
            return 0.0;

        return double(stats->allocated) / double(stats->allocs);
    }

    double pct_of(const MemoryStats& o) const
    {
        if ( !o.allocated )
            return 0.0;

        return double(stats->allocated) / double(o.allocated) * 100.0;
    }

    const MemoryStats& get_stats() const
    { return *stats; }

    double pct_caller() const
    {
        // FIXIT-L really, we should assert(!called) for root view
        if ( caller_stats )
            return pct_of(*caller_stats);

        return 0.0;
    }

    bool operator==(const View& rhs) const
    { return name == rhs.name; }

    bool operator!=(const View& rhs) const
    { return !(*this == rhs); }

    View(const ProfilerNode& node, View* parent = nullptr) :
        name(node.name), stats(new MemoryStats(node.get_stats().memory.stats.runtime))
    {
        if ( parent )
        {
            *parent->stats += *stats;
            caller_stats = parent->stats.get();
        }
    }
};

static const ProfilerSorter<View> sorters[] =
{
    { "", nullptr },
    {
        "allocations",
        [](const View& lhs, const View& rhs)
        { return lhs.allocs() >= rhs.allocs(); }
    },
    {
        "total_used",
        [](const View& lhs, const View& rhs)
        { return lhs.total() >= rhs.total(); }
    },
    {
        "avg_allocation",
        [](const View& lhs, const View& rhs)
        { return lhs.avg_alloc() >= rhs.avg_alloc(); }
    },
};

static bool include_fn(const ProfilerNode& node)
{ return node.get_stats().memory.stats.runtime; }

static void print_fn(StatsTable& t, const View& v)
{
    t << v.allocs();
    t << double(v.total()) / 1024.0;
    t << v.avg_alloc();
}

} // namespace memory_stats

void show_memory_profiler_stats(ProfilerNodeMap& nodes, const MemoryProfilerConfig& config)
{
    if ( !config.show )
        return;

    ProfilerBuilder<memory_stats::View> builder(memory_stats::include_fn);
    auto root = builder.build(nodes.get_root());

    if ( root.children.empty() && !root.view.stats )
        return;

    const auto& sorter = memory_stats::sorters[config.sort];

    ProfilerPrinter<memory_stats::View> printer(memory_stats::fields, memory_stats::print_fn, sorter);
    printer.print_table(s_memory_table_title, root, config.count, config.max_depth);
}

#ifdef UNIT_TEST

namespace
{
using MemoryEntry = ProfilerBuilder<memory_stats::View>::Entry;
using MemoryEntryVector = std::vector<MemoryEntry>;
using MemoryStatsVector = std::vector<MemoryStats>;
} // anonymous namespace

static inline bool operator==(const MemoryEntryVector& lhs, const MemoryStatsVector& rhs)
{
    if ( lhs.size() != rhs.size() )
        return false;

    for ( unsigned i = 0; i < lhs.size(); ++i )
        if ( *lhs[i].view.stats != rhs[i] )
            return false;

    return true;
}

static inline MemoryStats make_memory_stats(uint64_t allocations, uint64_t total_used)
{
    MemoryStats stats;
    stats.allocs = allocations;
    stats.allocated = total_used;

    return stats;
}

static inline MemoryEntry make_memory_entry(uint64_t allocations, uint64_t total_used)
{
    ProfilerNode node("");
    MemoryEntry entry(node);
    *entry.view.stats = make_memory_stats(allocations, total_used);

    return entry;
}

TEST_CASE( "memory stats", "[profiler][memory_profiler]" )
{
    MemoryStats stats = { 1, 2, 3, 4 };

    SECTION( "equality" )
    {
        auto stats_b = stats;

        CHECK( stats == stats_b );
        CHECK( stats != MemoryStats() );
    }

    SECTION( "operator+=" )
    {
        MemoryStats stats_b = { 5, 6, 7, 8 };
        stats += stats_b;

        CHECK( (stats.allocs == 6) );
        CHECK( (stats.deallocs == 8) );
        CHECK( (stats.allocated == 10) );
        CHECK( (stats.deallocated == 12) );
    }

    SECTION( "update" )
    {
        SECTION( "allocations" )
        {
            stats.update_allocs(10);

            CHECK( (stats.allocs == 2) );
            CHECK( (stats.deallocs == 2) ); // e.g. no change
            CHECK( (stats.allocated == 13) );
            CHECK( (stats.deallocated == 4) ); // e.g. no change

            SECTION( "deallocations" )
            {
                stats.update_deallocs(10);

                CHECK( (stats.allocs == 2) ); // e.g. no change
                CHECK( (stats.deallocs == 3) );
                CHECK( (stats.allocated == 13) ); // e.g. no change
                CHECK( (stats.deallocated == 14) );
            }
        }
    }

    SECTION( "reset" )
    {
        stats.reset();
        CHECK_FALSE( stats );
    }

    SECTION( "bool()" )
    {
        CHECK( stats );
        CHECK_FALSE( MemoryStats() );
    }
}

TEST_CASE( "memory profiler view", "[profiler][memory_profiler]" )
{
    ProfileStats the_stats;
    ProfilerNode node("foo");

    the_stats.memory.stats.runtime = { 1, 2, 100, 4 };
    node.set_stats(the_stats);

    SECTION( "no parent" )
    {
        memory_stats::View view(node);

        SECTION( "ctor sets members" )
        {
            CHECK( *view.stats == the_stats.memory.stats.runtime );
            CHECK( view.caller_stats == nullptr );
        }

        SECTION( "allocations" )
        {
            CHECK( view.allocs() == 1 );
        }

        SECTION( "total_used" )
        {
            CHECK( (view.total() == 100) );
        }

        SECTION( "avg_allocation" )
        {
            CHECK( (view.avg_alloc() == 100.0) );
        }

        SECTION( "pct_of" )
        {
            MemoryStats ms = { 0, 0, 200, 0 };

            CHECK( (view.pct_of(ms) == 50.0) );

            SECTION( "zero division" )
            {
                ms.allocated = 0;
                CHECK( (view.pct_of(ms) == 0.0) );
            }
        }
    }

    SECTION( "parent set" )
    {
        memory_stats::View parent(node);

        memory_stats::View child(node, &parent);
        CHECK( child.caller_stats == parent.stats.get() );

        parent.stats->allocated = 200;

        SECTION( "pct_caller" )
        {
            CHECK( (child.pct_caller() == 50.0) );
        }
    }
}

TEST_CASE( "memory profiler sorting", "[profiler][memory_profiler]" )
{
    using Sort = MemoryProfilerConfig::Sort;

    SECTION( "allocations" )
    {
        MemoryEntryVector entries {
            make_memory_entry(0, 5),
            make_memory_entry(1, 6),
            make_memory_entry(2, 4),
        };

        MemoryStatsVector expected {
            make_memory_stats(2, 4),
            make_memory_stats(1, 6),
            make_memory_stats(0, 5),
        };

        const auto& sorter = memory_stats::sorters[Sort::SORT_ALLOCATIONS];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);

        CHECK( entries == expected );
    }

    SECTION( "total_used" )
    {
        MemoryEntryVector entries {
            make_memory_entry(0, 5),
            make_memory_entry(1, 6),
            make_memory_entry(2, 4),
        };

        MemoryStatsVector expected {
            make_memory_stats(1, 6),
            make_memory_stats(0, 5),
            make_memory_stats(2, 4),
        };

        const auto& sorter = memory_stats::sorters[Sort::SORT_TOTAL_USED];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);

        CHECK( entries == expected );
    }

    SECTION( "avg_allocation" )
    {
        MemoryEntryVector entries {
            make_memory_entry(0, 0),
            make_memory_entry(10, 10),
            make_memory_entry(5, 10),
        };

        MemoryStatsVector expected {
            make_memory_stats(5, 10),
            make_memory_stats(10, 10),
            make_memory_stats(0, 0),
        };

        const auto& sorter = memory_stats::sorters[Sort::SORT_AVG_ALLOCATION];
        std::partial_sort(entries.begin(), entries.end(), entries.end(), sorter);

        CHECK( entries == expected );
    }
}

#endif
