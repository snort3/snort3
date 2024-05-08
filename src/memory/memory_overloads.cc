//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// memory_overloads.cc author Joel Cornett <jocornet@cisco.com>

#include "memory_overloads.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "profiler/memory_profiler_active_context.h"

#include "memory_allocator.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

extern THREAD_LOCAL unsigned instance_id;

namespace memory
{

// -----------------------------------------------------------------------------
// metadata
// -----------------------------------------------------------------------------

// This structure must be aligned to max_align_t as long as we are prefixing
// it to memory allocations so that the returned memory is also aligned.
struct alignas(max_align_t) Metadata
{
#if defined(REG_TEST) || defined(UNIT_TEST)
    static constexpr size_t SANITY_CHECK_VALUE = 0xabcdef;
    size_t sanity;
#endif

    // number of requested bytes
    size_t payload_size;
    uint32_t thread_id;
    // stat used to keep track of allocation/deallocation
    MemoryTracker* mp_inspector_stats = nullptr;

    // total number of bytes allocated, including Metadata header
    size_t total_size() const;
    void* payload_offset();

#if defined(REG_TEST) || defined(UNIT_TEST)
    bool valid() const
    { return sanity == SANITY_CHECK_VALUE; }
#endif

    Metadata(size_t = 0);

    static size_t calculate_total_size(size_t);

    template<typename Allocator>
    static Metadata* create(size_t);

    static Metadata* extract(void*);
};

inline size_t Metadata::total_size() const
{ return calculate_total_size(payload_size); }

inline void* Metadata::payload_offset()
{ return this + 1; }

inline Metadata::Metadata(size_t n) :
#if defined(REG_TEST) || defined(UNIT_TEST)
    sanity(SANITY_CHECK_VALUE),
#endif
    payload_size(n), thread_id(instance_id),
    mp_inspector_stats(&mp_active_context.get_default())
{ }

inline size_t Metadata::calculate_total_size(size_t n)
{ return sizeof(Metadata) + n; }

template<typename Allocator>
Metadata* Metadata::create(size_t n)
{
    auto meta =
        static_cast<Metadata*>(Allocator::allocate(calculate_total_size(n)));

    if ( !meta )
        return nullptr;

    // Trigger metadata ctor
    *meta = Metadata(n);

#if defined(REG_TEST) || defined(UNIT_TEST)
    assert(meta->valid());
#endif

    return meta;
}

Metadata* Metadata::extract(void* p)
{
    auto meta = static_cast<Metadata*>(p) - 1;

#if defined(REG_TEST) || defined(UNIT_TEST)
    assert(meta->valid());
#endif

    return meta;
}

// -----------------------------------------------------------------------------
// the meat
// -----------------------------------------------------------------------------

#ifdef REG_TEST
class ReentryContext
{
public:
    ReentryContext(bool& flag) :
        already_entered(flag), flag(flag)
    { flag = true; }

    ~ReentryContext()
    { flag = false; }

    bool is_reentry() const
    { return already_entered; }

private:
    const bool already_entered;
    bool& flag;
};
#endif

template<typename Allocator = MemoryAllocator>
struct Interface
{
    static void* allocate(size_t);
    static void deallocate(void*);

    static THREAD_LOCAL bool in_allocation_call;
};

template<typename Allocator>
void* Interface<Allocator>::allocate(size_t n)
{
#ifdef REG_TEST
    // prevent allocation reentry
    ReentryContext reentry_context(in_allocation_call);
    assert(!reentry_context.is_reentry());
#endif
    auto meta = Metadata::create<Allocator>(n);

    if ( !meta )
        return nullptr;

#ifdef ENABLE_MEMORY_PROFILER
    mp_active_context.update_allocs(meta->total_size());
#endif

    return meta->payload_offset();
}

template<typename Allocator>
void Interface<Allocator>::deallocate(void* p)
{
    if ( !p )
        return;

    auto meta = Metadata::extract(p);
    assert(meta);

#ifdef ENABLE_MEMORY_PROFILER
    if (!snort::Snort::is_exiting())
    {
        if (meta->mp_inspector_stats and meta->thread_id == instance_id) 
            meta->mp_inspector_stats->update_deallocs(meta->total_size());
        else
            mp_active_context.update_deallocs(meta->total_size());
    }
#endif

    Allocator::deallocate(meta);
}

template<typename Allocator>
THREAD_LOCAL bool Interface<Allocator>::in_allocation_call = false;

} //namespace memory

// -----------------------------------------------------------------------------
// new /delete replacements
// -----------------------------------------------------------------------------

// these don't have to be visible to operate as replacements

#ifdef ENABLE_MEMORY_PROFILER
void* operator new(size_t n)
{
    auto p = memory::Interface<>::allocate(n);
    if ( !p )
        throw std::bad_alloc();

    return p;
}

void* operator new[](size_t n)
{ return ::operator new(n); }

void* operator new(size_t n, const std::nothrow_t&) noexcept
{ return memory::Interface<>::allocate(n); }

void* operator new[](size_t n, const std::nothrow_t&) noexcept
{ return memory::Interface<>::allocate(n); }

void operator delete(void* p) noexcept
{ memory::Interface<>::deallocate(p); }

void operator delete[](void* p) noexcept
{ ::operator delete(p); }

void operator delete(void* p, const std::nothrow_t&) noexcept
{ ::operator delete(p); }

void operator delete[](void* p, const std::nothrow_t&) noexcept
{ ::operator delete[](p); }

void operator delete(void* p, size_t) noexcept
{ ::operator delete(p); }

void operator delete[](void* p, size_t) noexcept
{ ::operator delete[](p); }

void operator delete[](void* p, size_t, const std::nothrow_t&) noexcept
{ ::operator delete[](p); }

void operator delete(void* p, size_t, const std::nothrow_t&) noexcept
{ ::operator delete(p); }

#endif

// -----------------------------------------------------------------------------
// unit tests
// -----------------------------------------------------------------------------

#ifdef UNIT_TEST

namespace t_memory
{

struct AllocatorSpy
{
    static void* allocate(size_t n)
    { allocate_called = true; allocate_arg = n; return pool; }

    static void deallocate(void* p)
    { deallocate_called = true; deallocate_arg = p; }

    static void reset()
    {
        pool = nullptr;
        allocate_called = false;
        allocate_arg = 0;
        deallocate_called = false;
        deallocate_arg = nullptr;
    }

    static void* pool;
    static bool allocate_called;
    static size_t allocate_arg;
    static bool deallocate_called;
    static void* deallocate_arg;
};

void* AllocatorSpy::pool = nullptr;
bool AllocatorSpy::allocate_called = false;
size_t AllocatorSpy::allocate_arg = 0;
bool AllocatorSpy::deallocate_called = false;
void* AllocatorSpy::deallocate_arg = nullptr;

} // namespace t_memory

TEST_CASE( "memory metadata", "[memory]" )
{
    using namespace t_memory;

    AllocatorSpy::reset();
    constexpr size_t n = 1;
    char pool[sizeof(memory::Metadata) + n];

    SECTION( "create" )
    {
        AllocatorSpy::pool = pool;

        auto meta = memory::Metadata::create<AllocatorSpy>(n);

        CHECK( (void*)meta == (void*)pool );
        CHECK( true == meta->valid() );
        CHECK( meta->payload_size == n );
    }

    SECTION( "extract" )
    {
        auto meta_pool = reinterpret_cast<memory::Metadata*>(pool);
        meta_pool[0] = memory::Metadata(n);

        void* p = &meta_pool[1];

        auto meta = memory::Metadata::extract(p);

        CHECK( (void*)meta == (void*)pool );
        CHECK( meta->payload_offset() == p );
    }
}

TEST_CASE( "memory overloads", "[memory]" )
{
    using namespace t_memory;

    AllocatorSpy::reset();

    constexpr size_t n = 1;
    char pool[sizeof(memory::Metadata) + n];

    using Interface = memory::Interface<AllocatorSpy>;

    SECTION( "allocation" )
    {
        SECTION( "allocation failure" )
        {
            auto p = Interface::allocate(n);

            CHECK( p == nullptr );

            CHECK( AllocatorSpy::allocate_called );
            CHECK( AllocatorSpy::allocate_arg == memory::Metadata::calculate_total_size(n) );
        }

        SECTION( "success" )
        {
            AllocatorSpy::pool = pool;

            auto p = Interface::allocate(n);

            CHECK( p > (void*)pool );

            CHECK( AllocatorSpy::allocate_called );
            CHECK( AllocatorSpy::allocate_arg == memory::Metadata::calculate_total_size(n) );
        }
    }

    SECTION( "deallocation" )
    {
        SECTION( "nullptr" )
        {
            Interface::deallocate(nullptr);
            CHECK_FALSE( AllocatorSpy::deallocate_called );
        }

        SECTION( "success" )
        {
            auto meta_pool = reinterpret_cast<memory::Metadata*>(pool);
            meta_pool[0] = memory::Metadata(n);

            auto p = meta_pool[0].payload_offset();

            Interface::deallocate(p);

            CHECK( AllocatorSpy::deallocate_called );
            CHECK( AllocatorSpy::deallocate_arg == (void*)pool );
        }
    }
    AllocatorSpy::pool = nullptr;
    AllocatorSpy::deallocate_arg = nullptr;
}

#endif

