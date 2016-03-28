//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "memory_cap.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/thread.h"
#include "profiler/memory_profiler_active_context.h"

#include "memory_config.h"
#include "prune_handler.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

namespace memory
{

namespace
{

struct Tracker
{
    size_t allocated = 0;
    size_t deallocated = 0;

    size_t used() const
    {
        assert(allocated >= deallocated);
        return allocated - deallocated;
    }

    constexpr Tracker() = default;
};

THREAD_LOCAL Tracker s_tracker;

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

template<typename Tracker, typename Handler>
inline bool free_space(size_t requested, size_t cap, Tracker& trk, Handler& handler)
{
    assert(requested <= cap);
    const auto required = cap - requested;

    auto last_used = trk.used();
    while ( last_used > required )
    {
        handler();

        auto cur_used = trk.used();
        if ( cur_used >= last_used )
        {
            // handler failed to free any space, or worse, used more space
            return false;
        }

        last_used = cur_used;
    }

    return last_used <= required;
}

inline size_t calculate_threshold(size_t cap, size_t threshold)
{ return cap * threshold / 100; }

} // namespace

// -----------------------------------------------------------------------------
// per-thread configuration
// -----------------------------------------------------------------------------

size_t MemoryCap::thread_cap = 0;

// -----------------------------------------------------------------------------
// public interface
// -----------------------------------------------------------------------------

bool MemoryCap::free_space(size_t n)
{
    if ( !is_packet_thread() )
        return true;

    if ( !thread_cap )
        return true;

    const auto& config = *snort_conf->memory;
    return memory::free_space(n, thread_cap, s_tracker, prune_handler) || config.soft;
}

void MemoryCap::update_allocations(size_t n)
{
    s_tracker.allocated += n;
    mp_active_context.update_allocs(n);
}

void MemoryCap::update_deallocations(size_t n)
{
    s_tracker.deallocated += n;
    mp_active_context.update_deallocs(n);
}

void MemoryCap::calculate(unsigned num_threads)
{
    const MemoryConfig& config = *snort_conf->memory;

    if ( !config.cap )
        return;

    // FIXIT-M J right now the cap is relative, so we never run out of room
    // after startup, but this also means that the cap is not representative
    // of total memory used

    thread_cap = config.cap / num_threads;

    if ( !thread_cap )
        FatalError("per-thread memory cap is 0");

    DebugFormat(DEBUG_MEMORY, "per-thread memory cap set to %zu", thread_cap);
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
        CHECK( handler.calls == 2 );
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
