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

// memory_context.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "memory_context.h"

#include <mutex>
#include <new>

#include "memory_defs.h"
#include "memory_profiler_defs.h"
#include "memory_profiler_active_context.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

THREAD_LOCAL MemoryActiveContext mp_active_context;
static CombinedMemoryStats s_fallthrough_stats;


// -----------------------------------------------------------------------------
// memory manager interface
// -----------------------------------------------------------------------------

// get thread local default stats
const CombinedMemoryStats& MemoryProfiler::get_fallthrough_stats()
{ return s_fallthrough_stats; }

// thread local call
void MemoryProfiler::consolidate_fallthrough_stats()
{
    static std::mutex stats_mutex;
    std::lock_guard<std::mutex> lock(stats_mutex);

    s_fallthrough_stats += mp_active_context.get_fallback().stats;
}

// -----------------------------------------------------------------------------
// memory context
// -----------------------------------------------------------------------------

MemoryContext::MemoryContext(MemoryTracker& t) :
    saved(mp_active_context.get())
{ mp_active_context.set(&t); }

MemoryContext::~MemoryContext()
{ mp_active_context.set(saved); }

// -----------------------------------------------------------------------------
// memory pop
// -----------------------------------------------------------------------------

MemoryExclude::MemoryExclude() : saved(mp_active_context.unset()) { }

MemoryExclude::~MemoryExclude()
{ mp_active_context.set(saved); }


#ifdef UNIT_TEST

namespace
{

struct TestStackData
{
    int x;

    bool operator==(const TestStackData& o) const
    { return x == o.x; }

    bool operator!=(const TestStackData& o) const
    { return !(*this == o); }

    TestStackData& operator+=(const TestStackData& o)
    { x += o.x; return *this; }
};

} // anonymous namespace

TEST_CASE( "active context", "[profiler][active_context]" )
{
    ActiveContext<int> active;

    int a = 1;
    int b = 2;
    int fallback = 3;

    active.get_fallback() = fallback;

    CHECK( !active.is_set() );
    CHECK( active.get() == nullptr );
    CHECK( active.get_default() == fallback );

    CHECK( active.unset() == nullptr ); // does nothing
    CHECK( active.get() == nullptr );
    CHECK( active.get_default() == fallback );

    CHECK( active.set(&a) == nullptr );
    CHECK( active.is_set() );
    CHECK( active.get() == &a );
    CHECK( active.get_default() == a );

    CHECK( active.set(&b) == &a );
    CHECK( active.is_set() );
    CHECK( active.get() == &b );
    CHECK( active.get_default() == b );
}

#endif
