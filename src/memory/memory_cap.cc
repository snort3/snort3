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

THREAD_LOCAL MemoryConfig s_config;
THREAD_LOCAL Tracker s_tracker;
const MemoryConfig* s_main_config = nullptr;

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

template<typename Tracker, typename Handler>
inline bool free_space(size_t requested, size_t cap, Tracker& trk, Handler& handler)
{
    assert(requested <= cap);
    const auto required = cap - requested;

    if ( trk.used() > required )
        handler();

    return trk.used() <= required;
}

} // namespace

// -----------------------------------------------------------------------------
// public interface
// -----------------------------------------------------------------------------

bool MemoryCap::free_space(size_t n)
{
    if ( !is_packet_thread() )
        return true;

    const auto& config = s_config;

    if ( !config.enable )
        return true;

    return memory::free_space(n, config.cap, s_tracker, prune_handler);
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

// FIXIT-H J need to validate and print out warnings for configurations
// that result in very low values for per-thread memory
void MemoryCap::calculate(unsigned num_threads)
{
    if ( !snort_conf->memory->enable )
        return;

    s_config.enable = snort_conf->memory->enable;
    assert(snort_conf->memory->cap >= s_tracker.used());

    auto remaining = snort_conf->memory->cap - s_tracker.used();
    auto per_thread_cap = remaining / num_threads;

    assert(per_thread_cap > 0);

    s_config.cap = per_thread_cap;

    s_main_config = &s_config;

    DebugFormat(DEBUG_MEMORY,
        ("local memcap set: %zu startup cost, "
        "%zu available (%zu per-thread)\n"),
        s_tracker.used(), remaining, per_thread_cap, num_threads);
}

void MemoryCap::tinit()
{
    if ( s_main_config )
        s_config = *s_main_config;
}

} // namespace memory

#ifdef UNIT_TEST

namespace t_memory_cap
{

struct MockTracker
{
    size_t result;
    size_t used() const
    { return result; }
};

struct HandlerSpy
{
    bool called = false;
    size_t modify_tracker;
    MockTracker* tracker;

    void operator()()
    {
        called = true;
        if ( modify_tracker && tracker )
            tracker->result = modify_tracker;
    }

    HandlerSpy(size_t n, MockTracker& trk) :
        modify_tracker(n), tracker(&trk) { }
};

} // namespace t_memory_cap

TEST_CASE( "memory cap free space", "[memory]" )
{
    using namespace t_memory_cap;

    SECTION( "no handler call required" )
    {
        MockTracker tracker { 0 };
        HandlerSpy handler { 1, tracker };

        CHECK( memory::free_space(1, 1024, tracker, handler) );
        CHECK_FALSE( handler.called );
    }

    SECTION( "handler frees enough space" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { 1023, tracker };

        CHECK( memory::free_space(1, 1024, tracker, handler) );
        CHECK( handler.called );
        CHECK( tracker.result == handler.modify_tracker );
    }

    SECTION( "handler fails to free enough space" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { 0, tracker };

        CHECK_FALSE( memory::free_space(1, 1024, tracker, handler) );
        CHECK( handler.called );
        CHECK( tracker.result == 1024 );
    }
}

#endif
