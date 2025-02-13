//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "log/messages.h"
#include "main/thread.h"
#include "managers/module_manager.h"
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
}

THREAD_LOCAL const Trace* memory_trace = nullptr;

#ifndef REG_TEST
void Periodic::register_handler(PeriodicHook, void*, uint16_t, uint32_t) { }
#endif

void ModuleManager::accumulate_module(const char*) { }

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

    void get_process_total(uint64_t& e, uint64_t& t) override
    { e = ++epoch; t = total; }

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

void set_thread_type(SThreadType)
{ pkt_thread = false; }

static void free_space()
{
    pkt_thread = true;
    MemoryCap::free_space();
    pkt_thread = false;
}

static MemoryCounts& get_main_stats()
{
    return MemoryCap::get_mem_stats();
}

static MemoryCounts& get_pkt_stats()
{
    pkt_thread = true;
    MemoryCounts& res = MemoryCap::get_mem_stats();
    pkt_thread = false;
    return res;
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

    const MemoryCounts& mc = get_main_stats();
    const MemoryCounts& pc = get_pkt_stats();
    CHECK(mc.start_up_use == start);

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
    UNSIGNED_LONGS_EQUAL(2, pc.reap_decrease);

    free_space();
    UNSIGNED_LONGS_EQUAL(1, fd.flows);
    UNSIGNED_LONGS_EQUAL(2, pc.reap_decrease);

    periodic_check(); // still over the limit
    CHECK(heap->epoch == 3);

    free_space();
    UNSIGNED_LONGS_EQUAL(0, fd.flows);

    heap->total = cap; // no longer over the limit
    periodic_check();
    CHECK(heap->epoch == 4);

    free_space(); // abort
    UNSIGNED_LONGS_EQUAL(0, fd.flows);
    UNSIGNED_LONGS_EQUAL(3, pc.reap_decrease);

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
    UNSIGNED_LONGS_EQUAL(3, pc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(4, pc.reap_increase);

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
    UNSIGNED_LONGS_EQUAL(0, fd.flows);
    UNSIGNED_LONGS_EQUAL(3, pc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(6, pc.reap_increase);

    UNSIGNED_LONGS_EQUAL(start, mc.start_up_use);
    UNSIGNED_LONGS_EQUAL(cap + 1, mc.max_in_use);
    UNSIGNED_LONGS_EQUAL(cap, mc.cur_in_use);

    UNSIGNED_LONGS_EQUAL(heap->epoch, mc.epochs);
    UNSIGNED_LONGS_EQUAL(heap->alloc, pc.allocated);
    UNSIGNED_LONGS_EQUAL(heap->dealloc, pc.deallocated);

    UNSIGNED_LONGS_EQUAL(4, pc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(5, pc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, pc.reap_failures);
    UNSIGNED_LONGS_EQUAL(3, pc.reap_aborts);

    heap->total = start;
    MemoryCap::stop();
    CHECK(mc.epochs == heap->epoch);
    CHECK(mc.cur_in_use == start);
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

    const MemoryCounts& pc = get_pkt_stats();
    UNSIGNED_LONGS_EQUAL(1, pc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(3, pc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, pc.reap_failures);
    UNSIGNED_LONGS_EQUAL(1, pc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(0, pc.reap_increase);

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

    const MemoryCounts& pc = get_pkt_stats();
    UNSIGNED_LONGS_EQUAL(2, pc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(2, pc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, pc.reap_failures);
    UNSIGNED_LONGS_EQUAL(11, pc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(0, pc.reap_increase);

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

    const MemoryCounts& pc = get_pkt_stats();

    fd.flows = 1;
    heap->total = cap + 1;
    periodic_check();

    free_space();
    CHECK(fd.flows == 0);

    free_space(); // reap failure
    CHECK(fd.flows == -1);
    UNSIGNED_LONGS_EQUAL(1, pc.reap_decrease);

    fd.flows = 1;
    heap->total = cap + 1;
    periodic_check();

    free_space();
    CHECK(fd.flows == 0);

    heap->alloc += 3;

    free_space(); // reap failure, reap_increase update
    CHECK(fd.flows == -1);
    UNSIGNED_LONGS_EQUAL(1, pc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(2, pc.reap_increase);

    fd.flows = 1;
    heap->total = cap + 1;
    periodic_check();

    free_space();
    CHECK(fd.flows == 0);

    heap->alloc += 2;

    free_space(); // reap failure, reap_increase update
    CHECK(fd.flows == -1);
    UNSIGNED_LONGS_EQUAL(1, pc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(3, pc.reap_increase);

    UNSIGNED_LONGS_EQUAL(3, pc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(6, pc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(3, pc.reap_failures);

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

    const MemoryCounts& pc = get_pkt_stats();
    UNSIGNED_LONGS_EQUAL(1, pc.reap_cycles);
    UNSIGNED_LONGS_EQUAL(2, pc.reap_attempts);
    UNSIGNED_LONGS_EQUAL(0, pc.reap_failures);
    UNSIGNED_LONGS_EQUAL(2, pc.reap_decrease);
    UNSIGNED_LONGS_EQUAL(0, pc.reap_increase);

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

