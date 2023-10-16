//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "memory_cap.h"

#include <sys/resource.h>

#include <atomic>
#include <cassert>
#include <vector>

#include "log/messages.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/thread.h"
#include "time/periodic.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include "heap_interface.h"
#include "memory_config.h"
#include "memory_module.h"

using namespace snort;

namespace memory
{

// -----------------------------------------------------------------------------
// private
// -----------------------------------------------------------------------------

static std::vector<MemoryCounts> pkt_mem_stats;

static MemoryConfig config;
static size_t limit = 0;

static bool over_limit = false;
static std::atomic<uint64_t> current_epoch { 0 };

static THREAD_LOCAL uint64_t start_dealloc = 0;
static THREAD_LOCAL uint64_t start_alloc = 0;
static THREAD_LOCAL uint64_t start_epoch = 0;

static HeapInterface* heap = nullptr;
static PruneHandler pruner;

static void epoch_check(void*)
{
    uint64_t epoch, total;
    heap->get_process_total(epoch, total);

    bool prior = over_limit;
    over_limit = limit and total > limit;

    if ( prior != over_limit )
        trace_logf(memory_trace, nullptr, "Epoch=%lu, memory=%lu (%s)\n", epoch, total, over_limit?"over":"under");
    if ( over_limit )
        current_epoch = epoch;
    else
        current_epoch = 0;

    MemoryCounts& mc = MemoryCap::get_mem_stats();

    if ( total > mc.max_in_use )
        mc.max_in_use = total;

    mc.cur_in_use = total;
    mc.epochs++;

    // for reporting / tracking only
    uint64_t all, act, res, ret;
    heap->get_aux_counts(all, act, res, ret);

    mc.app_all = all;
    mc.active = act;
    mc.resident = res;
    mc.retained = ret;
}

// -----------------------------------------------------------------------------
// test access
// -----------------------------------------------------------------------------

#ifdef REG_TEST
static unsigned count_down = 1;

static void test_pkt_check()
{
    assert(is_packet_thread());

    if ( !config.enabled )
        return;

    if ( get_instance_id() != 0 )
        return;

    if ( !config.interval )
        return;

    if ( --count_down )
        return;
    else
        count_down = config.interval;

    epoch_check(nullptr);
}
#endif

#if defined(REG_TEST) || defined(UNIT_TEST)
void MemoryCap::test_main_check()
{
    assert(in_main_thread());
    epoch_check(nullptr);
}
#endif

// -----------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------

void MemoryCap::init(unsigned n)
{
    assert(in_main_thread());
    pkt_mem_stats.resize(n);

#ifdef UNIT_TEST
    pkt_mem_stats[0] = { };
#endif
}

void MemoryCap::term()
{
    pkt_mem_stats.resize(0);
    delete heap;
    heap = nullptr;
}

void MemoryCap::set_heap_interface(HeapInterface* h)
{ heap = h; }

void MemoryCap::set_pruner(PruneHandler p)
{ pruner = p; }

void MemoryCap::start(const MemoryConfig& c, PruneHandler ph)
{
    assert(in_main_thread());

    config = c;

    if ( !heap )
        heap = HeapInterface::get_instance();

    heap->main_init();

    if ( !config.enabled )
        return;

    if ( !pruner )
        pruner = ph;

    limit = config.cap * config.threshold / 100;
    over_limit = false;
    current_epoch = 0;

#ifndef REG_TEST
    Periodic::register_handler(epoch_check, nullptr, 0, config.interval);
#endif

    epoch_check(nullptr);

    MemoryCounts& mc = get_mem_stats();
    mc.start_up_use = mc.cur_in_use;
}

void MemoryCap::stop()
{ epoch_check(nullptr); }

void MemoryCap::thread_init()
{
    heap->thread_init();
    start_dealloc = 0;
    start_epoch = 0;
}

void MemoryCap::thread_term()
{
    MemoryCounts& mc = get_mem_stats();
    heap->get_thread_allocs(mc.allocated, mc.deallocated);
}

MemoryCounts& MemoryCap::get_mem_stats()
{
    // main thread stats do not overlap with packet threads
    if ( in_main_thread() )
        return pkt_mem_stats[0];

    auto id = get_instance_id();
    return pkt_mem_stats[id];
}

void MemoryCap::free_space()
{
    assert(is_packet_thread());

#ifdef REG_TEST
    test_pkt_check();
#endif

    MemoryCounts& mc = get_mem_stats();
    heap->get_thread_allocs(mc.allocated, mc.deallocated);

    // Not already pruning
    if ( !start_dealloc )
    {
        // Not over the limit
        if ( !current_epoch )
            return;
        // Already completed pruning in the epoch
        if ( current_epoch == start_epoch )
            return;

        // Start pruning for this epoch
        start_dealloc = mc.deallocated;
        start_alloc = mc.allocated;
        start_epoch = current_epoch;
        mc.reap_cycles++;
    }

    uint64_t dealloc = mc.deallocated - start_dealloc;
    uint64_t alloc = mc.allocated - start_alloc;

    // Has the process gone under the limit
    if ( !current_epoch )
    {
        if ( dealloc > alloc)
            mc.reap_decrease += dealloc - alloc;
        else
            mc.reap_increase += alloc - dealloc;
        start_dealloc = 0;
        mc.reap_aborts++;
        return;
    }
    // Has this thread freed enough outside of pruning
    else if ( dealloc > alloc and ( ( dealloc - alloc ) >= config.prune_target ) )
    {
        mc.reap_decrease += dealloc - alloc;
        start_dealloc = 0;
        return;
    }

    ++mc.reap_attempts;

    bool prune_success = pruner();

    // Updates values after pruning
    heap->get_thread_allocs(mc.allocated, mc.deallocated);
    alloc = mc.allocated - start_alloc;
    dealloc = mc.deallocated - start_dealloc;

    if ( prune_success )
    {
        // Pruned the target amount, so stop pruning for this epoch
        if ( dealloc > alloc and ( ( dealloc - alloc ) >= config.prune_target ) )
        {
            mc.reap_decrease += dealloc - alloc;
            start_dealloc = 0;
        }
    }
    else
    {
        // Failed to prune, so stop pruning
        if ( dealloc > alloc)
            mc.reap_decrease += dealloc - alloc;
        else
            mc.reap_increase += alloc - dealloc;
        start_dealloc = 0;
        ++mc.reap_failures;
    }
}

// required to capture any update in final epoch
// which happens after packet threads have stopped
void MemoryCap::update_pegs(PegCount* pc)
{
    MemoryCounts* mp = (MemoryCounts*)pc;
    const MemoryCounts& mc = get_mem_stats();

    if ( config.enabled )
    {
        mp->epochs = mc.epochs;
        mp->cur_in_use = mc.cur_in_use;
    }
    else
    {
        mp->allocated = 0;
        mp->deallocated = 0;
    }
}

// called at startup and shutdown
void MemoryCap::print(bool verbose, bool init)
{
    if ( !config.enabled )
        return;

    MemoryCounts& mc = get_mem_stats();

    if ( init and (verbose or mc.start_up_use) )
    {
        LogLabel("memory");
        LogCount("pruning threshold", limit);
        LogCount("start up use", mc.start_up_use);
    }

    if ( limit and (mc.max_in_use > limit) )
        LogCount("process over limit", mc.max_in_use - limit);

    if ( verbose )
    {
        struct rusage ru;
        getrusage(RUSAGE_SELF, &ru);
        LogCount("max rss", ru.ru_maxrss * 1024);
    }
}

void MemoryCap::dump_mem_stats(ControlConn* ctrlcon)
{
    heap->print_stats(ctrlcon);
}
} // namespace memory

