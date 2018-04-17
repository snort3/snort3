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

// memory_manager.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <new>

#include "main/thread.h"

#include "memory_allocator.h"
#include "memory_cap.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

namespace memory
{

// -----------------------------------------------------------------------------
// metadata
// -----------------------------------------------------------------------------

// NOTE: This structure must be aligned to max_align_t as long as we are prepending
//       it to memory allocations so that the returned memory is also aligned.
struct alignas(max_align_t) Metadata
{
#if defined(REG_TEST) || defined(UNIT_TEST)
    static constexpr size_t SANITY_CHECK_VALUE = 0xabcdef;
    size_t sanity;
#endif

    // number of requested bytes
    size_t payload_size;

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
    payload_size(n)
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
    assert(p);

    auto meta = static_cast<Metadata*>(p) - 1;

#if defined(REG_TEST) || defined(UNIT_TEST)
    assert(meta->valid());
#endif

    return meta;
}

// -----------------------------------------------------------------------------
// the meat
// -----------------------------------------------------------------------------

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

template<typename Allocator = MemoryAllocator, typename Cap = MemoryCap>
struct Interface
{
    static void* allocate(size_t);
    static void deallocate(void*);

    static THREAD_LOCAL bool in_allocation_call;
};

template<typename Allocator, typename Cap>
void* Interface<Allocator, Cap>::allocate(size_t n)
{
    // prevent allocation reentry
    ReentryContext reentry_context(in_allocation_call);
    assert(!reentry_context.is_reentry());

    if ( !Cap::free_space(Metadata::calculate_total_size(n)) )
        return nullptr;

    auto meta = Metadata::create<Allocator>(n);
    if ( !meta )
        return nullptr;

    Cap::update_allocations(meta->total_size());
    return meta->payload_offset();
}

template<typename Allocator, typename Cap>
void Interface<Allocator, Cap>::deallocate(void* p)
{
    if ( !p )
        return;

    auto meta = Metadata::extract(p);
    assert(meta);

    Cap::update_deallocations(meta->total_size());
    Allocator::deallocate(meta);
}

template<typename Allocator, typename Cap>
THREAD_LOCAL bool Interface<Allocator, Cap>::in_allocation_call = false;

} //namespace memory

// -----------------------------------------------------------------------------
// new /delete replacements
// -----------------------------------------------------------------------------

// these don't have to be visible to operate as replacements

#ifndef NO_MEM_MGR
void* operator new(size_t n)
{
    auto p = memory::Interface<>::allocate(n);
    if ( !p )
        throw std::bad_alloc();

    return p;
}

void* operator new(size_t n, const std::nothrow_t&) noexcept
{ return memory::Interface<>::allocate(n); }

void operator delete(void* p) noexcept
{ memory::Interface<>::deallocate(p); }

void operator delete(void* p, const std::nothrow_t&) noexcept
{ ::operator delete(p); }

void* operator new[](size_t n)
{ return ::operator new(n); }

void* operator new[](size_t n, const std::nothrow_t& tag) noexcept
{ return ::operator new(n, tag); }

void operator delete[](void* p) noexcept
{ ::operator delete(p); }

void operator delete[](void* p, const std::nothrow_t&) noexcept
{ ::operator delete[](p); }

// C++14 delete operators are a special case and must be explicitly exported
// since we're compiling as C++11 but must capture these for external libraries
void operator delete(void* p, size_t) noexcept;
SO_PUBLIC void operator delete(void* p, size_t) noexcept
{ ::operator delete(p); }

void operator delete[](void* p, size_t) noexcept;
SO_PUBLIC void operator delete[](void* p, size_t) noexcept
{ ::operator delete[](p); }
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

struct CapSpy
{
    static bool free_space(size_t n)
    {
        free_space_called = true;
        free_space_arg = n;
        return free_space_result;
    }

    static void update_allocations(size_t n)
    {
        update_allocations_called = true;
        update_allocations_arg = n;
    }

    static void update_deallocations(size_t n)
    {
        update_deallocations_called = true;
        update_deallocations_arg = n;
    }

    static void reset()
    {
        free_space_called = false;
        free_space_arg = 0;
        free_space_result = false;

        update_allocations_called = false;
        update_allocations_arg = 0;

        update_deallocations_called = false;
        update_deallocations_arg = 0;
    }

    static bool free_space_called;
    static size_t free_space_arg;
    static bool free_space_result;

    static bool update_allocations_called;
    static size_t update_allocations_arg;

    static bool update_deallocations_called;
    static size_t update_deallocations_arg;
};

bool CapSpy::free_space_called = false;
size_t CapSpy::free_space_arg = 0;
bool CapSpy::free_space_result = false;

bool CapSpy::update_allocations_called = false;
size_t CapSpy::update_allocations_arg = 0;

bool CapSpy::update_deallocations_called = false;
size_t CapSpy::update_deallocations_arg = 0;

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
        CHECK( meta->valid() );
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

TEST_CASE( "memory manager interface", "[memory]" )
{
    using namespace t_memory;

    AllocatorSpy::reset();
    CapSpy::reset();

    constexpr size_t n = 1;
    char pool[sizeof(memory::Metadata) + n];

    using Interface = memory::Interface<AllocatorSpy, CapSpy>;

    SECTION( "allocation" )
    {
        SECTION( "free space failure" )
        {
            auto p = Interface::allocate(n);

            CHECK( p == nullptr );

            CHECK( CapSpy::free_space_called );
            CHECK( CapSpy::free_space_arg == memory::Metadata::calculate_total_size(n) );

            CHECK_FALSE( AllocatorSpy::allocate_called );
            CHECK_FALSE( CapSpy::update_allocations_called );
        }

        SECTION( "allocation failure" )
        {
            CapSpy::free_space_result = true;

            auto p = Interface::allocate(n);

            CHECK( p == nullptr );

            CHECK( CapSpy::free_space_called );
            CHECK( CapSpy::free_space_arg == memory::Metadata::calculate_total_size(n) );

            CHECK( AllocatorSpy::allocate_called );
            CHECK( AllocatorSpy::allocate_arg == memory::Metadata::calculate_total_size(n) );

            CHECK_FALSE( CapSpy::update_allocations_called );
        }

        SECTION( "success" )
        {
            CapSpy::free_space_result = true;
            AllocatorSpy::pool = pool;

            auto p = Interface::allocate(n);

            CHECK( p > (void*)pool );

            CHECK( CapSpy::free_space_called );
            CHECK( CapSpy::free_space_arg == memory::Metadata::calculate_total_size(n) );

            CHECK( AllocatorSpy::allocate_called );
            CHECK( AllocatorSpy::allocate_arg == memory::Metadata::calculate_total_size(n) );

            CHECK( CapSpy::update_allocations_called );
            CHECK( CapSpy::update_allocations_arg == memory::Metadata::calculate_total_size(n) );
        }
    }

    SECTION( "deallocation" )
    {
        SECTION( "nullptr" )
        {
            Interface::deallocate(nullptr);

            CHECK_FALSE( AllocatorSpy::deallocate_called );
            CHECK_FALSE( CapSpy::update_deallocations_called );
        }

        SECTION( "success" )
        {
            auto meta_pool = reinterpret_cast<memory::Metadata*>(pool);
            meta_pool[0] = memory::Metadata(n);

            auto p = meta_pool[0].payload_offset();

            Interface::deallocate(p);

            CHECK( AllocatorSpy::deallocate_called );
            CHECK( AllocatorSpy::deallocate_arg == (void*)pool );
            CHECK( CapSpy::update_deallocations_called );
            CHECK( CapSpy::update_deallocations_arg == memory::Metadata::calculate_total_size(n) );
        }
    }
    AllocatorSpy::pool = nullptr;
    AllocatorSpy::deallocate_arg = nullptr;
}

#endif
