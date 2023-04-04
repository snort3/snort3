//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "time/periodic.h"
#include "trace/trace_api.h"

#include "memory/heap_interface.h"
#include "memory/memory_config.h"

using namespace snort;

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

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

void Periodic::register_handler(PeriodicHook, void*, uint16_t, uint32_t) { }

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

static int flows;

static bool pruner()
{ return --flows >= 0; }

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
    void setup() override
    {
        MemoryCap::init(1);
        MemoryCap::set_pruner(pruner);
    }

    void teardown() override
    {
        MemoryCap::term();
        flows = 0;
    }
};

TEST(memory_off, disabled)
{
    MemoryConfig config { 0, 100, 0, 1, false };
    MemoryCap::start(config, pruner);

    free_space();

    CHECK(flows == 0);

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

    CHECK(flows == 0);

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
    MockHeap* heap = nullptr;

    void setup() override
    {
        MemoryCap::init(1);
        heap = new MockHeap;
        MemoryCap::set_heap_interface(heap);
    }

    void teardown() override
    {
        MemoryCap::term();
        heap = nullptr;
        flows = 0;
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
    CHECK(flows == 0);

    MemoryCap::stop();
    CHECK(heap->epoch == 3);
}

TEST(memory, prune1)
{
    const uint64_t cap = 100;
    const uint64_t start = 50;
    heap->total = start;

    MemoryConfig config { cap, 100, 0, 1, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    CHECK(mc.start_up_use == start);

    flows = 2;
    free_space();
    CHECK(flows == 2);

    heap->total = cap + 1;
    periodic_check();
    CHECK(heap->epoch == 2);

    CHECK(flows == 2);
    free_space();
    CHECK(flows == 1);

    heap->total = cap;
    periodic_check();
    CHECK(heap->epoch == 3);

    heap->alloc++;
    heap->dealloc++;

    free_space();
    CHECK(flows == 0);

    heap->dealloc++;
    free_space();
    CHECK(flows == 0);

    CHECK(mc.start_up_use == start);
    CHECK(mc.max_in_use == cap + 1);
    CHECK(mc.cur_in_use == cap);

    CHECK(mc.epochs == heap->epoch);
    CHECK(mc.allocated == heap->alloc);
    CHECK(mc.deallocated == heap->dealloc);

    CHECK(mc.reap_cycles == 1);
    CHECK(mc.reap_attempts == 2);
    CHECK(mc.reap_failures == 0);
    CHECK(mc.pruned == 2);

    heap->total = start;
    MemoryCap::stop();
    CHECK(mc.epochs == heap->epoch);
    CHECK(mc.cur_in_use == start);
}

TEST(memory, prune3)
{
    uint64_t cap = 100;
    MemoryConfig config { cap, 100, 0, 1, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    flows = 3;
    heap->total = cap + 1;

    periodic_check();
    CHECK(heap->epoch == 2);

    CHECK(flows == 3);
    free_space();
    CHECK(flows == 2);

    free_space();
    CHECK(flows == 1);

    free_space();
    CHECK(flows == 0);

    heap->total = cap;
    periodic_check();
    CHECK(heap->epoch == 3);

    heap->dealloc++;
    free_space();
    CHECK(flows == 0);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    CHECK(mc.reap_cycles == 1);
    CHECK(mc.reap_attempts == 3);
    CHECK(mc.reap_failures == 0);
    CHECK(mc.pruned == 1);

    MemoryCap::stop();
}

TEST(memory, two_cycles)
{
    uint64_t cap = 100;
    MemoryConfig config { cap, 100, 0, 1, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    flows = 3;
    heap->total = cap + 1;
    periodic_check();

    CHECK(flows == 3);
    free_space();  // prune 1 flow
    CHECK(flows == 2);

    heap->dealloc++;
    free_space();  // reset state
    CHECK(flows == 2);

    free_space();  // at most 1 reap cycle per epoch
    CHECK(flows == 2);

    heap->total = cap;
    periodic_check();
    free_space();
    CHECK(flows == 2);

    heap->total = cap + 10;
    periodic_check();
    free_space();
    CHECK(flows == 1);

    heap->total = cap;
    heap->dealloc += 10;
    periodic_check();

    free_space();
    CHECK(flows == 1);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    CHECK(mc.reap_cycles == 2);
    CHECK(mc.reap_attempts == 2);
    CHECK(mc.reap_failures == 0);
    CHECK(mc.pruned == 11);

    MemoryCap::stop();
}

TEST(memory, reap_failure)
{
    const uint64_t cap = 100;
    const uint64_t start = 50;
    heap->total = start;

    MemoryConfig config { cap, 100, 0, 2, true };
    MemoryCap::start(config, pruner);
    MemoryCap::thread_init();

    flows = 1;
    heap->total = cap + 1;

    periodic_check();

    CHECK(flows == 1);
    free_space();
    CHECK(flows == 0);

    heap->dealloc++;
    free_space();
    CHECK(flows == -1);

    const MemoryCounts& mc = MemoryCap::get_mem_stats();
    CHECK(mc.reap_cycles == 1);
    CHECK(mc.reap_attempts == 2);
    CHECK(mc.reap_failures == 1);
    CHECK(mc.pruned == 1);

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

