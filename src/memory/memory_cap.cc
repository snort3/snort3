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
#include "main/thread.h"
#include "profiler/memory_profiler_active_context.h"
#include "memory_config.h"
#include "prune_handler.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

template<typename Tracker, typename Handler>
static inline bool free_space(size_t requested, size_t cap, Tracker& trk, Handler& handler)
{
    assert(requested <= cap);
    const auto required = cap - requested;

    if ( trk.used() > required )
        handler();

    return trk.used() <= required;
}

namespace memory
{

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static THREAD_LOCAL Tracker s_tracker;

// -----------------------------------------------------------------------------
// public interface
// -----------------------------------------------------------------------------

bool DefaultCap::free_space(size_t n)
{
    if ( !is_packet_thread() )
        return true;

    const auto& config = *snort_conf->memory;

    if ( !config.enable || !config.cap )
        return true;

    return ::free_space(n, config.cap, s_tracker, prune_handler);
}

void DefaultCap::update_allocations(size_t n)
{
    if ( is_packet_thread() )
        s_tracker.allocated += n;

    mp_active_context.update_allocs(n);
}

void DefaultCap::update_deallocations(size_t n)
{
    if ( is_packet_thread() )
        s_tracker.deallocated += n;

    mp_active_context.update_deallocs(n);
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

        CHECK( ::free_space(1, 1024, tracker, handler) );
        CHECK_FALSE( handler.called );
    }

    SECTION( "handler frees enough space" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { 1023, tracker };

        CHECK( ::free_space(1, 1024, tracker, handler) );
        CHECK( handler.called );
        CHECK( tracker.result == handler.modify_tracker );
    }

    SECTION( "handler fails to free enough space" )
    {
        MockTracker tracker { 1024 };
        HandlerSpy handler { 0, tracker };

        CHECK_FALSE( ::free_space(1, 1024, tracker, handler) );
        CHECK( handler.called );
        CHECK( tracker.result == 1024 );
    }
}

#endif
