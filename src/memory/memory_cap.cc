//--------------------------------------------------------------------------
// Copyright (C) 2016-2021 Cisco and/or its affiliates. All rights reserved.
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

// memory_cap.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "memory_cap.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "profiler/memory_profiler_active_context.h"
#include "utils/stats.h"

#include "memory_config.h"
#include "memory_module.h"
#include "prune_handler.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

namespace memory
{

namespace
{

struct Tracker
{
    void allocate(size_t n)
    { mem_stats.allocated += n; ++mem_stats.allocations; }

    void deallocate(size_t n)
    {
        mem_stats.deallocated += n; ++mem_stats.deallocations;
        assert(mem_stats.deallocated <= mem_stats.allocated);
        assert(mem_stats.deallocations <= mem_stats.allocations);
        assert(mem_stats.allocated or !mem_stats.allocations);
    }

    size_t used() const
    {
        if ( mem_stats.allocated < mem_stats.deallocated )
        {
            assert(false);
            return 0;
        }
        return mem_stats.allocated - mem_stats.deallocated;
    }
};

static Tracker s_tracker;

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

template<typename Tracker, typename Handler>
inline bool free_space(size_t requested, size_t cap, Tracker& trk, Handler& handler)
{
    if ( requested > cap )
    {
        return false;
    }

    auto used = trk.used();

    if ( used + requested <= cap )
        return true;

    ++mem_stats.reap_attempts;

    while ( used + requested > cap )
    {
        handler();
        auto tmp = trk.used();

        if ( tmp >= used )
        {
            ++mem_stats.reap_failures;
            return false;
        }
        used = tmp;
    }
    return true;
}

inline size_t calculate_threshold(size_t cap, size_t threshold)
{ return cap * threshold / 100; }

} // namespace

// -----------------------------------------------------------------------------
// per-thread configuration
// -----------------------------------------------------------------------------

size_t MemoryCap::thread_cap = 0;
size_t MemoryCap::preemptive_threshold = 0;

// -----------------------------------------------------------------------------
// public interface
// -----------------------------------------------------------------------------

void MemoryCap::free_space(size_t n)
{
    if ( !is_packet_thread() )
        return;

    if ( !thread_cap )
        return;

    static THREAD_LOCAL bool entered = false;

    if ( entered )
        return;

    entered = true;
    memory::free_space(n, thread_cap, s_tracker, prune_handler);
    entered = false;
}

static size_t fudge_it(size_t n)
{
    return ((n >> 7) + 1) << 7;
}

void MemoryCap::update_allocations(size_t n)
{
    if (n == 0)
        return;

    size_t k = n;
    n = fudge_it(n);
    free_space(n);
    mem_stats.total_fudge += (n - k);
    s_tracker.allocate(n);
    auto in_use = s_tracker.used();
    if ( in_use > mem_stats.max_in_use )
        mem_stats.max_in_use = in_use;
    mp_active_context.update_allocs(n);
}

void MemoryCap::update_deallocations(size_t n)
{
    if (n == 0)
      return;

    n = fudge_it(n);
    s_tracker.deallocate(n);
    mp_active_context.update_deallocs(n);
}

bool MemoryCap::over_threshold()
{
    if ( !preemptive_threshold )
        return false;

    return s_tracker.used() >= preemptive_threshold;
}

// FIXIT-L this should not be called while the packet threads are running.
// once reload is implemented for the memory manager, the configuration
// model will need to be updated

void MemoryCap::calculate()
{
    assert(!is_packet_thread());
    const MemoryConfig& config = *SnortConfig::get_conf()->memory;

    thread_cap = config.cap;
    preemptive_threshold = memory::calculate_threshold(thread_cap, config.threshold);
}

void MemoryCap::print()
{
    if ( !MemoryModule::is_active() )
        return;

    bool verbose = SnortConfig::log_verbose();

    if ( verbose or mem_stats.allocations )
        LogLabel("memory (heap)");

    if ( verbose )
    {
        LogMessage("    thread cap: %zu\n", thread_cap);
        LogMessage("    thread preemptive threshold: %zu\n", preemptive_threshold);
    }

    if ( mem_stats.allocations )
    {
        LogMessage("    main thread usage: %zu\n", s_tracker.used());
        LogMessage("    allocations: %" PRIu64 "\n", mem_stats.allocations);
        LogMessage("    deallocations: %" PRIu64 "\n", mem_stats.deallocations);
    }
}

} // namespace memory

#ifdef UNIT_TEST

namespace t_memory_cap
{

struct MockTracker
{
    size_t result = 0;
    size_t used() const
    { return result; }

    MockTracker(size_t r) : result { r } { }
    MockTracker() = default;
};

struct HandlerSpy
{
    size_t calls = 0;
    ssize_t modifier;
    MockTracker* tracker;

    void operator()()
    {
        ++calls;
        if ( modifier && tracker )
            tracker->result += modifier;
    }

    HandlerSpy(ssize_t n, MockTracker& trk) :
        modifier(n), tracker(&trk) { }
};

} // namespace t_memory_cap

TEST_CASE( "memory cap free space", "[memory]" )
{
    using namespace t_memory_cap;

    SECTION( "no handler call required" )
    {
        MockTracker tracker;
        HandlerSpy handler { 0, tracker };

        CHECK( memory::free_space(1, 1024, tracker, handler) );
        CHECK( handler.calls == 0 );
    }

    SECTION( "handler frees enough space the first time" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { -5, tracker };

        CHECK( memory::free_space(1, 1024, tracker, handler) );
        CHECK( handler.calls == 1 );
    }

    SECTION( "handler needs to be called multiple times to free up space" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { -1, tracker };

        CHECK( memory::free_space(2, 1024, tracker, handler) );
        CHECK( (handler.calls == 2) );
    }

    SECTION( "handler fails to free enough space" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { 0, tracker };

        CHECK_FALSE( memory::free_space(1, 1024, tracker, handler) );
        CHECK( handler.calls == 1 );
    }

    SECTION( "handler actually uses more space" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { 5, tracker };
        CHECK_FALSE( memory::free_space(1, 1024, tracker, handler) );
        CHECK( handler.calls == 1 );
    }
}

#endif
