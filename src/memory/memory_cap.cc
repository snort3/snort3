//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "log/log_stats.h"
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

static THREAD_LOCAL MemoryCounts thread_mem_stats;

static MemoryConfig config;
static size_t limit = 0;

static bool over_limit = false;
static std::atomic<uint64_t> current_epoch { 0 };
static std::atomic<uint64_t> start_up_use { 0 };
static std::atomic<uint64_t> max_in_use { 0 };

// The most recent epoch reported by jemalloc
static std::atomic<uint64_t> latest_epoch { 0 };

static THREAD_LOCAL uint64_t start_dealloc = 0;
static THREAD_LOCAL uint64_t start_alloc = 0;
static THREAD_LOCAL uint64_t start_epoch = 0;

static HeapInterface* heap = nullptr;
static PruneHandler pruner;

static void epoch_check(void*)
{
    uint64_t epoch, total;
    heap->get_process_total(epoch, total, true);

    bool prior = over_limit;
    over_limit = limit and total > limit;

    if ( prior != over_limit )
        trace_logf(memory_trace, nullptr, "Epoch=%lu, memory=%lu (%s)\n", epoch, total, over_limit?"over":"under");
    if ( over_limit )
        current_epoch = epoch;
    else
        current_epoch = 0;

    latest_epoch = epoch;

    // Track max here so no peak is missed between stats reads.
    uint64_t cur_max = max_in_use.load(std::memory_order_relaxed);
    while ( total > cur_max &&
            !max_in_use.compare_exchange_weak(cur_max, total, std::memory_order_relaxed) )
        ;
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

void MemoryCap::init(unsigned)
{
    assert(in_main_thread());
    thread_mem_stats = { };
}

void MemoryCap::term()
{
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

    // Capture startup memory use now that the first epoch has been bumped.
    // Done here rather than in epoch_check() to keep epoch_check() free of
    // any peg-count side effects.
    uint64_t epoch_unused, total;
    heap->get_process_total(epoch_unused, total, false);
    start_up_use = total;
}

void MemoryCap::stop()
{
    epoch_check(nullptr);
    update_global_stats();
}

void MemoryCap::thread_init()
{
    heap->thread_init();
    thread_mem_stats = { };
    start_dealloc = 0;
    start_epoch = 0;
}

void MemoryCap::thread_term()
{
    MemoryCounts& mc = get_mem_stats();
    heap->get_thread_allocs(mc.allocated, mc.deallocated);
}

MemoryCounts& MemoryCap::get_mem_stats()
{ return thread_mem_stats; }

MemoryCounts& MemoryCap::get_global_stats()
{ return thread_mem_stats; }


void MemoryCap::free_space()
{
    assert(is_packet_thread());

#ifdef REG_TEST
    test_pkt_check();
#endif

    MemoryCounts& mc = get_mem_stats();

    // Thread-local; no cross-thread reads, so plain assignment is safe.
    uint64_t a, d;
    heap->get_thread_allocs(a, d);
    mc.allocated = a;
    mc.deallocated = d;

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

    mc.reap_attempts++;

    bool prune_success = pruner();

    // Updates values after pruning
    heap->get_thread_allocs(a, d);
    mc.allocated = a;
    mc.deallocated = d;
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
        mc.reap_failures++;
    }
}

void MemoryCap::reset_thread_stats()
{
    if ( !is_packet_thread() )
        return;

    MemoryCounts& mc = get_mem_stats();
    mc.reap_cycles = 0;
    mc.reap_attempts = 0;
    mc.reap_failures = 0;
    mc.reap_aborts = 0;
    mc.reap_decrease = 0;
    mc.reap_increase = 0;

    start_dealloc = 0;
    start_alloc = mc.allocated;
    start_epoch = 0;
}


void MemoryCap::update_global_stats(bool dump_stats)
{
    if ( !heap )
        return;

    // Populate heap pegs into the calling thread's stats. For thread 0 these
    // are included in the framework's per-thread aggregation during dump_stats;
    // other threads have 0 for heap fields so the totals are correct.
    MemoryCounts& mc = thread_mem_stats;

    uint64_t epoch, total;
    heap->get_process_total(epoch, total, false);

    mc.cur_in_use = total;
    mc.max_in_use = max_in_use;
    mc.start_up_use = start_up_use;

    // epochs is only meaningful for dump_stats; skip on the perfmon periodic path.
    if ( dump_stats )
    {
        if ( epoch > latest_epoch )
            latest_epoch = epoch;
        mc.epochs = latest_epoch;
    }

    // for reporting / tracking only
    uint64_t all, act, res, ret;
    heap->get_aux_counts(all, act, res, ret);

    mc.app_all = all;
    mc.active = act;
    mc.resident = res;
    mc.retained = ret;
}

// called at startup and shutdown
void MemoryCap::print(bool verbose, bool init)
{
    if ( !config.enabled )
        return;

    update_global_stats();
    MemoryCounts& mc = get_global_stats();

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

void MemoryCap::heap_profile_config(bool enable, uint64_t sample_rate)
{
    heap->profile_config(enable, sample_rate);
}

void MemoryCap::dump_heap_profile(ControlConn* ctrlcon)
{
    heap->dump_profile(ctrlcon);
}

void MemoryCap::show_heap_profile_config(ControlConn* ctrlcon)
{
    heap->show_profile_config(ctrlcon);
}

} // namespace memory
