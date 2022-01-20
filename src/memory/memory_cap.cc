//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

#include <malloc.h>
#include <sys/resource.h>

#include <cassert>
#include <vector>

#ifdef HAVE_JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#include "memory_cap.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/thread.h"
#include "profiler/memory_profiler_active_context.h"
#include "utils/stats.h"

#include "memory_config.h"
#include "memory_module.h"
#include "prune_handler.h"

using namespace snort;

namespace memory
{

static MemoryCounts ctl_mem_stats;
static std::vector<MemoryCounts> pkt_mem_stats;

namespace
{

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

#ifdef HAVE_JEMALLOC
static size_t get_usage(MemoryCounts& mc)
{
    static THREAD_LOCAL uint64_t* alloc_ptr = nullptr, * dealloc_ptr = nullptr;

    if ( !alloc_ptr )
    {
        size_t sz = sizeof(alloc_ptr);
        // __STRDUMP_DISABLE__
        mallctl("thread.allocatedp", (void*)&alloc_ptr, &sz, nullptr, 0);
        mallctl("thread.deallocatedp", (void*)&dealloc_ptr, &sz, nullptr, 0);
        // __STRDUMP_ENABLE__
    }
    mc.allocated = *alloc_ptr;
    mc.deallocated = *dealloc_ptr;

    if ( mc.allocated > mc.deallocated )
    {
        size_t usage =  mc.allocated - mc.deallocated;

        if ( usage > mc.max_in_use )
            mc.max_in_use = usage;

        return usage;
    }
    return 0;
}
#else
static size_t get_usage(const MemoryCounts& mc)
{
#ifdef ENABLE_MEMORY_OVERLOADS
    assert(mc.allocated >= mc.deallocated);
    return mc.allocated - mc.deallocated;

#else
    UNUSED(mc);
    return 0;
#endif
}
#endif

template<typename Handler>
inline void free_space(size_t cap, Handler& handler)
{
    MemoryCounts& mc = memory::MemoryCap::get_mem_stats();
    size_t usage = get_usage(mc);

    if ( usage < cap )
        return;

    ++mc.reap_attempts;

    if ( handler() )
        return;

    ++mc.reap_failures;
}

inline size_t calculate_threshold(size_t cap, size_t threshold)
{ return cap * threshold / 100; }

} // namespace

// -----------------------------------------------------------------------------
// per-thread configuration
// -----------------------------------------------------------------------------

size_t MemoryCap::limit = 0;

// -----------------------------------------------------------------------------
// public interface
// -----------------------------------------------------------------------------

void MemoryCap::setup(const MemoryConfig& config, unsigned n)
{
    assert(!is_packet_thread());
    limit = memory::calculate_threshold(config.cap, config.threshold);
    pkt_mem_stats.resize(n);
}

void MemoryCap::cleanup()
{
    pkt_mem_stats.resize(0);
}

MemoryCounts& MemoryCap::get_mem_stats()
{
    if ( !is_packet_thread() )
        return ctl_mem_stats;

    auto id = get_instance_id();
    return pkt_mem_stats[id];
}

void MemoryCap::free_space()
{
    assert(is_packet_thread());

    if ( !limit )
        return;

    memory::free_space(limit, prune_handler);
}

#ifdef ENABLE_MEMORY_OVERLOADS
void MemoryCap::allocate(size_t n)
{
    MemoryCounts& mc = memory::MemoryCap::get_mem_stats();

    mc.allocated += n;
    ++mc.allocations;

    assert(mc.allocated >= mc.deallocated);
    auto in_use = mc.allocated - mc.deallocated;

    if ( in_use > mc.max_in_use )
        mc.max_in_use = in_use;

#ifdef ENABLE_MEMORY_PROFILER
    mp_active_context.update_allocs(n);
#endif
}

void MemoryCap::deallocate(size_t n)
{
    MemoryCounts& mc = memory::MemoryCap::get_mem_stats();

    // std::thread causes an extra deallocation in packet
    // threads so the below asserts don't hold
    if ( mc.allocated >= mc.deallocated + n )
    {
        mc.deallocated += n;
        ++mc.deallocations;
    }

#if 0
    assert(mc.deallocated <= mc.allocated);
    assert(mc.deallocations <= mc.allocations);
    assert(mc.allocated or !mc.allocations);
#endif

#ifdef ENABLE_MEMORY_PROFILER
    mp_active_context.update_deallocs(n);
#endif
}
#endif

void MemoryCap::print(bool verbose, bool print_all)
{
    if ( !MemoryModule::is_active() )
        return;

    MemoryCounts& mc = get_mem_stats();
    uint64_t usage = get_usage(mc);

    if ( verbose or usage )
        LogLabel("memory (heap)");

    if ( verbose and print_all )
        LogCount("pruning threshold", limit);

    LogCount("main thread usage", usage);
    LogCount("allocations", mc.allocations);
    LogCount("deallocations", mc.deallocations);

    if ( verbose )
    {
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        LogCount("max_rss", ru.ru_maxrss * 1024);
    }
}

} // namespace memory

