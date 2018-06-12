//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
    size_t allocated = 0;
    size_t deallocated = 0;

    uint64_t allocations = 0;
    uint64_t deallocations = 0;

    void allocate(size_t n)
    { allocated += n; ++allocations; }

    void deallocate(size_t n)
    { deallocated += n; ++deallocations; }

    size_t used() const
    {
        // FIXIT-H this assertion fails at analyzer.cc:93 / starting packet thread
        // {allocated = 0, deallocated = 48, allocations = 0, deallocations = 1}
        //assert(allocated >= deallocated);

        if ( allocated < deallocated )
            return 0;

        return allocated - deallocated;
    }

    constexpr Tracker() = default;
};

static THREAD_LOCAL Tracker s_tracker;

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

    while ( used + requested > cap )
    {
        handler();

        // check if the handler freed any space
        auto tmp = trk.used();
        if ( tmp >= used )
        {
            // nope
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

bool MemoryCap::free_space(size_t n)
{
    if ( !is_packet_thread() )
        return true;

    if ( !thread_cap )
        return true;

    const auto& config = *snort::SnortConfig::get_conf()->memory;
    return memory::free_space(n, thread_cap, s_tracker, prune_handler) || config.soft;
}

void MemoryCap::update_allocations(size_t n)
{
    s_tracker.allocate(n);
    mp_active_context.update_allocs(n);
}

void MemoryCap::update_deallocations(size_t n)
{
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

void MemoryCap::calculate(unsigned num_threads)
{
    assert(!is_packet_thread());
    const MemoryConfig& config = *snort::SnortConfig::get_conf()->memory;

    auto main_thread_used = s_tracker.used();

    if ( !config.cap )
    {
        thread_cap = preemptive_threshold = 0;
        return;
    }

    if ( main_thread_used > config.cap )
    {
        ParseError("main thread memory usage (%zu) is greater than cap\n", main_thread_used);
        return;
    }

    auto real_cap = config.cap - main_thread_used;
    thread_cap = real_cap / num_threads;

    // FIXIT-L do we want to add some fixed overhead to allow the packet threads to
    // startup and preallocate flows and whatnot?

    if ( !thread_cap )
    {
        ParseError("per-thread memory cap is 0");
        return;
    }

    if ( config.threshold )
        preemptive_threshold = memory::calculate_threshold(thread_cap, config.threshold);
}

void MemoryCap::print()
{
    if ( !MemoryModule::is_active() )
        return;

    const MemoryConfig& config = *snort::SnortConfig::get_conf()->memory;

    if ( snort::SnortConfig::log_verbose() or s_tracker.allocations )
        LogLabel("memory (heap)");

    if ( snort::SnortConfig::log_verbose() )
    {
        LogMessage("    global cap: %zu\n", config.cap);
        LogMessage("    global preemptive threshold percent: %zu\n", config.threshold);
        LogMessage("    cap type: %s\n", config.soft? "soft" : "hard");
    }

    if ( s_tracker.allocations )
    {
        LogMessage("    main thread usage: %zu\n", s_tracker.used());
        LogMessage("    allocations: %" PRIu64 "\n", s_tracker.allocations);
        LogMessage("    deallocations: %" PRIu64 "\n", s_tracker.deallocations);
        LogMessage("    thread cap: %zu\n", thread_cap);
        LogMessage("    preemptive threshold: %zu\n", preemptive_threshold);
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
