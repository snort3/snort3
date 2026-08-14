//--------------------------------------------------------------------------
// Copyright (C) 2023-2026 Cisco and/or its affiliates. All rights reserved.
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

// memory_cap_test.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "memory/memory_cap.h"

#include <cstring>
#include <string>
#include <vector>

#include "log/messages.h"
#include "main/thread.h"
#include "main/thread_config.h"
#include "memory/memory_module.h"
#include "profiler/profiler.h"
#include "time/periodic.h"
#include "trace/trace_api.h"

#include "memory/heap_interface.h"
#include "memory/memory_config.h"

using namespace snort;

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace memory;
using IndexVec = std::vector<unsigned>;

static std::vector<PegCount> shown_counts;
static std::string shown_module;

static int find_peg_idx(const PegInfo* pegs, const char* name)
{
    for ( int i = 0; pegs[i].name; ++i )
    {
        if ( strcmp(pegs[i].name, name) == 0 )
            return i;
    }
    return -1;
}

//--------------------------------------------------------------------------
// stubs
//--------------------------------------------------------------------------

namespace snort
{
// LCOV_EXCL_START
void LogCount(char const*, uint64_t, FILE*) { }
void LogLabel(const char*, FILE*) { }

void TraceApi::filter(snort::Packet const&) { }
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }

uint8_t snort::TraceApi::get_constraints_generation() { return 0; }
// LCOV_EXCL_STOP

unsigned get_instance_id()
{ return 0; }

unsigned ThreadConfig::get_instance_max()
{ return 0; }

}

void show_stats(PegCount* counts, const PegInfo*, unsigned n, const char* module_name)
{
    shown_counts.assign(counts, counts + n);
    shown_module = module_name ? module_name : "";
}
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

#ifndef REG_TEST
void Periodic::register_handler(PeriodicHook, void*, uint16_t, uint32_t) { }
#endif

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------

class MockHeap : public HeapInterface
{
public:
    void main_init() override
    { main_init_calls++; }

    void thread_init() override
    { thread_init_calls++; }

    void get_process_total(uint64_t& e, uint64_t& t, bool bump_epoch) override
    {
        t = total;
        if ( bump_epoch )
            e = ++epoch;
        else
            e = epoch;
    }

    void get_thread_allocs(uint64_t& a, uint64_t& d) override
    { a = alloc; d = dealloc; }

    uint64_t alloc = 2, dealloc = 1;
    uint64_t epoch = 0, total = 0;

    unsigned main_init_calls = 0;
    unsigned thread_init_calls = 0;
};

static void periodic_check()
{ MemoryCap::test_main_check(); }

struct TestFlowData
{
    int flows = 0;
    unsigned flow_to_alloc_factor = 1;
};

static bool pruner()
{
    MockHeap* heap = (MockHeap*)mock().getData("heap").getObjectPointer();
    TestFlowData* fd = (TestFlowData*)mock().getData("flows").getObjectPointer();
    if ( heap && 0 < fd->flows)
        heap->dealloc += fd->flow_to_alloc_factor;
    fd->flows--;
    return fd->flows >= 0;
}

static bool pkt_thread = false;

namespace snort
{

SThreadType get_thread_type()
{ return pkt_thread ? STHREAD_TYPE_PACKET : STHREAD_TYPE_MAIN; }

}

static void free_space()
{
    pkt_thread = true;
    MemoryCap::free_space();
    pkt_thread = false;
}

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

TEST_GROUP(memory_off)
{
    TestFlowData fd;

    void setup() override
    {
        fd = {};
        mock().setDataObject("flows", "TestFlowData", &fd);
        mock().setDataObject("heap", "MockHeap", nullptr);
        MemoryCap::init(1);
        MemoryCap::set_pruner(pruner);
    }

    void teardown() override
    {
        MemoryCap::term();
    }
};

TEST(memory_off, disabled)
{
    MemoryConfig config { 0, 100, 0, 1, false };
    MemoryCap::start(config, pruner);

    free_space();

    CHECK(fd.flows == 0);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    CHECK(mc.start_up_use == 0);
    CHECK(mc.epochs == 0);
    CHECK(mc.reap_cycles == 0);

    MemoryCap::stop();
}

TEST(memory_off, nerfed)
{
    MemoryConfig config { 100, 100, 0, 1, false };
    MemoryCap::start(config, pruner);

    free_space();

    CHECK(fd.flows == 0);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    CHECK(mc.start_up_use == 0);
    CHECK(mc.epochs == 0);
    CHECK(mc.reap_cycles == 0);

    MemoryCap::stop();
}

//--------------------------------------------------------------------------
// tests
//--------------------------------------------------------------------------

TEST_GROUP(memory)
{
    TestFlowData fd;
    MockHeap* heap = nullptr;

    void setup() override
    {
        fd = {0, 1};
        shown_counts.clear();
        shown_module.clear();
        mock().setDataObject("flows", "TestFlowData", &fd);
        MemoryCap::init(1);
        heap = new MockHeap;
        MemoryCap::set_heap_interface(heap);
        mock().setDataObject("heap", "MockHeap", heap);
    }

    void teardown() override
    {
        MemoryCap::term();
    }
};

TEST(memory, default_enabled)
{
    MemoryConfig config { 0, 100, 0, 1, true };
    MemoryCap::start(config, pruner);

    CHECK(heap->epoch == 1);
    CHECK(heap->main_init_calls == 1);

    CHECK(heap->thread_init_calls == 0);
    MemoryCap::thread_init();
    CHECK(heap->thread_init_calls == 1);
    CHECK(heap->main_init_calls == 1);

    periodic_check();
    CHECK(heap->epoch == 2);
    CHECK(fd.flows == 0);

    MemoryCap::stop();
    CHECK(heap->epoch == 3);
}

TEST(memory, prune1)
{
    const uint64_t cap = 100;
    const uint64_t start = 50;
    heap->total = start;

    MemoryConfig config { (size_t)cap, 100, 0, 2, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    MemoryCap::update_global_stats();
    const MemoryCounts& gmc = MemoryCap::get_global_stats();
    CHECK(gmc.start_up_use == start);

    fd.flows = 3;
    free_space();
    UNSIGNED_LONGS_EQUAL(3, fd.flows);

    heap->total = cap + 1; // over the limit
    periodic_check();
    CHECK(heap->epoch == 2);

    UNSIGNED_LONGS_EQUAL(3, fd.flows);
    free_space(); // this prunes 1
    UNSIGNED_LONGS_EQUAL(2, fd.flows);

    free_space(); // finish pruning
    UNSIGNED_LONGS_EQUAL(1, fd.flows);
    UNSIGNED_LONGS_EQUAL(2, mc.reap_decrease);

    free_space();
    UNSIGNED_LONGS_EQUAL(1, fd.flows);
    UNSIGNED_LONGS_EQUAL(2, mc.reap_decrease);

    periodic_check(); // still over the limit
    CHECK(heap->epoch == 3);

    free_space();
    UNSIGNED_LONGS_EQUAL(0, fd.flows);

    heap->total = cap; // no longer over the limit
    periodic_check();
    CHECK(heap->epoch == 4);

    free_space(); // abort
    UNSIGNED_LONGS_EQUAL(0, fd.flows);
    UNSIGNED_LONGS_EQUAL(3, mc.reap_decrease);

    heap->total = cap + 1; // over the limit
    periodic_check();
    CHECK(heap->epoch == 5);

    fd.flows = 1;
    free_space();
    UNSIGNED_LONGS_EQUAL(0, fd.flows);

    heap->total = cap; // no longer over the limit
    periodic_check();
    CHECK(heap->epoch == 6);

    heap->alloc += 5;

    free_space(); // abort, reap_increase update
    UNSIGNED_LONGS_EQUAL(0, fd.flows);
    UNSIGNED_LONGS_EQUAL(3, mc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(4, mc.reap_increase);

    heap->total = cap + 1; // over the limit
    periodic_check();
    CHECK(heap->epoch == 7);

    fd.flows = 1;
    free_space();
    UNSIGNED_LONGS_EQUAL(0, fd.flows);

    heap->total = cap; // no longer over the limit
    periodic_check();
    CHECK(heap->epoch == 8);

    heap->alloc += 3;

    free_space(); // abort, reap_increase update
    memory::MemoryCap::update_global_stats();
    UNSIGNED_LONGS_EQUAL(0, fd.flows);
    UNSIGNED_LONGS_EQUAL(3, mc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(6, mc.reap_increase);

    UNSIGNED_LONGS_EQUAL(start, gmc.start_up_use);
    UNSIGNED_LONGS_EQUAL(cap + 1, gmc.max_in_use);
    UNSIGNED_LONGS_EQUAL(cap, gmc.cur_in_use);

    UNSIGNED_LONGS_EQUAL(heap->epoch, gmc.epochs);

    UNSIGNED_LONGS_EQUAL(4, gmc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(5, gmc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, gmc.reap_failures);
    UNSIGNED_LONGS_EQUAL(3, gmc.reap_aborts);

    heap->total = start;
    MemoryCap::stop();
    memory::MemoryCap::update_global_stats();
    CHECK(gmc.epochs == heap->epoch);
    CHECK(gmc.cur_in_use == start);
}

TEST(memory, prune3)
{
    uint64_t cap = 100;
    MemoryConfig config { (size_t)cap, 100, 0, 1, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    fd.flows = 3;
    fd.flow_to_alloc_factor = 0;
    heap->total = cap + 1;

    periodic_check();
    CHECK(heap->epoch == 2);

    CHECK(fd.flows == 3);
    free_space();
    CHECK(fd.flows == 2);

    free_space();
    CHECK(fd.flows == 1);

    fd.flow_to_alloc_factor = 1;
    free_space();
    CHECK(fd.flows == 0);

    heap->total = cap;
    periodic_check();
    CHECK(heap->epoch == 3);

    free_space();
    CHECK(fd.flows == 0);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    UNSIGNED_LONGS_EQUAL(1, mc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(3, mc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, mc.reap_failures);
    UNSIGNED_LONGS_EQUAL(1, mc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(0, mc.reap_increase);

    MemoryCap::stop();
}

TEST(memory, two_cycles)
{
    uint64_t cap = 100;
    MemoryConfig config { (size_t)cap, 100, 0, 1, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    fd.flows = 3;
    heap->total = cap + 1;
    periodic_check();

    CHECK(fd.flows == 3);
    free_space();  // prune 1 flow and stop pruning from target
    CHECK(fd.flows == 2);

    free_space();
    CHECK(fd.flows == 2);

    heap->total = cap;
    periodic_check();
    free_space();
    CHECK(fd.flows == 2);

    fd.flow_to_alloc_factor = 10;
    heap->total = cap + 1;
    periodic_check();
    free_space();
    CHECK(fd.flows == 1);

    free_space();
    CHECK(fd.flows == 1);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    UNSIGNED_LONGS_EQUAL(2, mc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(2, mc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, mc.reap_failures);
    UNSIGNED_LONGS_EQUAL(11, mc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(0, mc.reap_increase);

    MemoryCap::stop();
}

TEST(memory, reap_failure)
{
    const uint64_t cap = 100;
    const uint64_t start = 50;
    heap->total = start;

    MemoryConfig config { (size_t)cap, 100, 0, 2, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    const MemoryCounts& mc = MemoryCap::get_mem_stats();

    fd.flows = 1;
    heap->total = cap + 1;
    periodic_check();

    free_space();
    CHECK(fd.flows == 0);

    free_space(); // reap failure
    CHECK(fd.flows == -1);
    UNSIGNED_LONGS_EQUAL(1, mc.reap_decrease);

    fd.flows = 1;
    heap->total = cap + 1;
    periodic_check();

    free_space();
    CHECK(fd.flows == 0);

    heap->alloc += 3;

    free_space(); // reap failure, reap_increase update
    CHECK(fd.flows == -1);
    UNSIGNED_LONGS_EQUAL(1, mc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(2, mc.reap_increase);

    fd.flows = 1;
    heap->total = cap + 1;
    periodic_check();

    free_space();
    CHECK(fd.flows == 0);

    heap->alloc += 2;

    free_space(); // reap failure, reap_increase update
    CHECK(fd.flows == -1);
    UNSIGNED_LONGS_EQUAL(1, mc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(3, mc.reap_increase);

    UNSIGNED_LONGS_EQUAL(3, mc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(6, mc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(3, mc.reap_failures);

    MemoryCap::stop();
}

TEST(memory, reap_freed_outside_of_pruning)
{
    const uint64_t cap = 100;
    const uint64_t start = 50;
    heap->total = start;

    MemoryConfig config { (size_t)cap, 100, 0, 2, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    fd.flows = 2;
    heap->total = cap + 1;

    periodic_check();

    UNSIGNED_LONGS_EQUAL(2, fd.flows);
    free_space();
    UNSIGNED_LONGS_EQUAL(1, fd.flows);

    heap->alloc++;

    free_space();
    UNSIGNED_LONGS_EQUAL(0, fd.flows);

    heap->dealloc++;

    free_space();
    UNSIGNED_LONGS_EQUAL(0, fd.flows);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    UNSIGNED_LONGS_EQUAL(1, mc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(2, mc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, mc.reap_failures);
    UNSIGNED_LONGS_EQUAL(2, mc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(0, mc.reap_increase);

    MemoryCap::stop();
}

TEST(memory, module_show_stats_preserves_aggregated_thread_alloc_counts)
{
    heap->total = 50;

    MemoryConfig config { 100, 100, 0, 1, true };
    MemoryCap::start(config, pruner);

    MemoryModule mod;
    mod.init_stats();

    const PegInfo* pegs = mod.get_pegs();
    const int start_up_idx = find_peg_idx(pegs, "start_up_use");
    const int cur_in_use_idx = find_peg_idx(pegs, "cur_in_use");
    const int epochs_idx = find_peg_idx(pegs, "epochs");
    const int allocated_idx = find_peg_idx(pegs, "allocated");
    const int deallocated_idx = find_peg_idx(pegs, "deallocated");

    CHECK(start_up_idx >= 0);
    CHECK(cur_in_use_idx >= 0);
    CHECK(epochs_idx >= 0);
    CHECK(allocated_idx >= 0);
    CHECK(deallocated_idx >= 0);

    std::vector<PegCount> aggregated(mod.get_num_counts(), 0);
    aggregated[start_up_idx] = 999;
    aggregated[cur_in_use_idx] = 999;
    aggregated[epochs_idx] = 999;
    aggregated[allocated_idx] = 240;
    aggregated[deallocated_idx] = 240;
    mod.set_dump_stats_results(aggregated);

    heap->total = 75;
    periodic_check();

    mod.show_stats();

    STRCMP_EQUAL("memory", shown_module.c_str());
    UNSIGNED_LONGS_EQUAL(50, shown_counts[start_up_idx]);
    UNSIGNED_LONGS_EQUAL(75, shown_counts[cur_in_use_idx]);
    UNSIGNED_LONGS_EQUAL(2, shown_counts[epochs_idx]);
    UNSIGNED_LONGS_EQUAL(240, shown_counts[allocated_idx]);
    UNSIGNED_LONGS_EQUAL(240, shown_counts[deallocated_idx]);

    MemoryCap::stop();
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
