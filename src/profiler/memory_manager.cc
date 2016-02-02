//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// memory_manager.cc author Joel Cornett <jocornet@cisco.com>

#include "memory_manager.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <cstdlib>
#include <mutex>
#include <new>

#include "memory_defs.h"
#include "memory_profiler_defs.h"
#include "active_context.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

// -----------------------------------------------------------------------------
// memory active context
// -----------------------------------------------------------------------------

class MemoryActiveContext : public ActiveContext<MemoryTracker>
{
public:
    void update_allocs(size_t n)
    { get_default().update_allocs(n); }

    void update_deallocs(size_t n)
    { get_default().update_deallocs(n); }
};

// -----------------------------------------------------------------------------
// metadata
// -----------------------------------------------------------------------------

struct MemoryMetadata
{
    size_t sanity;
    size_t size;

    bool valid() const
    { return sanity == SANITY_CHECK; }

    size_t true_size() const
    { return size + sizeof(MemoryMetadata); }

    static MemoryMetadata* construct(void*, size_t true_size);
    static MemoryMetadata* extract(void*);

    static const size_t SANITY_CHECK;
};

inline MemoryMetadata* MemoryMetadata::construct(void* p, size_t true_size)
{
    auto meta = static_cast<MemoryMetadata*>(p);
    meta->size = true_size - sizeof(MemoryMetadata);
    meta->sanity = SANITY_CHECK;

    return meta;
}

inline MemoryMetadata* MemoryMetadata::extract(void* p)
{ return static_cast<MemoryMetadata*>(p) - 1; }

const size_t MemoryMetadata::SANITY_CHECK = 0xabcdef;

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static THREAD_LOCAL MemoryActiveContext s_active_context;
static CombinedMemoryStats s_fallthrough_stats;


// -----------------------------------------------------------------------------
// alloc/dealloc
// -----------------------------------------------------------------------------

static inline void* s_allocate(size_t n)
{
    const auto true_size = n + sizeof(MemoryMetadata);
    auto p = malloc(true_size);

    if ( !p )
        return p;

    auto meta = MemoryMetadata::construct(p, true_size);

    s_active_context.update_allocs(true_size);

    return meta + 1;
}

static inline void s_deallocate(void* p) noexcept
{
    if ( !p )
        return;

    auto meta = MemoryMetadata::extract(p);
    assert(meta->valid());

    s_active_context.update_deallocs(meta->true_size());

    free(meta);
}


// -----------------------------------------------------------------------------
// operator new/delete replacements
// -----------------------------------------------------------------------------

void* operator new(size_t n)
{
    auto p = s_allocate(n);
    if ( !p )
        throw std::bad_alloc();

    return p;
}

void* operator new(size_t n, const std::nothrow_t&) noexcept
{ return s_allocate(n); }

void operator delete(void* p) noexcept
{ s_deallocate(p); }

void* operator new[](size_t n)
{ return ::operator new(n); }

void operator delete[](void* p) noexcept
{ ::operator delete(p); }


// -----------------------------------------------------------------------------
// memory manager interface
// -----------------------------------------------------------------------------

// get thread local default stats
const CombinedMemoryStats& Memory::get_fallthrough_stats()
{ return s_fallthrough_stats; }

// thread local call
void Memory::consolidate_fallthrough_stats()
{
    static std::mutex stats_mutex;
    std::lock_guard<std::mutex> lock(stats_mutex);

    s_fallthrough_stats += s_active_context.get_fallback().stats;
}

THREAD_LOCAL bool Memory::is_runtime = false;

// -----------------------------------------------------------------------------
// memory context
// -----------------------------------------------------------------------------

MemoryContext::MemoryContext(MemoryTracker& t) :
    saved(s_active_context.get())
{ s_active_context.set(&t); }

MemoryContext::~MemoryContext()
{ s_active_context.set(saved); }

// -----------------------------------------------------------------------------
// memory pop
// -----------------------------------------------------------------------------

MemoryExclude::MemoryExclude() : saved(s_active_context.unset()) { }

MemoryExclude::~MemoryExclude()
{ s_active_context.set(saved); }


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

TEST_CASE( "memory metadata", "[profiler][memory]" )
{
    MemoryMetadata arena[2];
    MemoryMetadata* meta = arena;

    SECTION( "valid" )
    {
        CHECK_FALSE( meta->valid() ); // sanity hasn't been set yet
        meta->sanity = MemoryMetadata::SANITY_CHECK;
        CHECK( meta->valid() );
    }

    SECTION( "true_size" )
    {
        meta->size = 0;
        CHECK( meta->true_size() == sizeof(MemoryMetadata) );
    }

    SECTION( "construct" )
    {
        auto m = MemoryMetadata::construct(arena, sizeof(MemoryMetadata) + 1);
        CHECK( m->size == 1 );
        CHECK( m->true_size() == sizeof(MemoryMetadata) + 1 );
        CHECK( m->sanity == MemoryMetadata::SANITY_CHECK );
    }

    SECTION( "extract" )
    {
        meta->sanity = MemoryMetadata::SANITY_CHECK;
        meta->size = 1;

        void* p = &arena[1];
        auto m = MemoryMetadata::extract(p);

        CHECK( m->size == 1 );
        CHECK( m->true_size() == sizeof(MemoryMetadata) + 1 );
        CHECK( m->valid() );
    }
}

TEST_CASE( "memory context", "[profiler][memory]" )
{
    // Can't really unit test this without messing with the memory tracking
    // CHECK( false );
}

TEST_CASE( "memory pop", "[profiler][memory]" )
{
    // Can't really unit test this without messing with the memory tracking
    // CHECK( false );
}

#endif
