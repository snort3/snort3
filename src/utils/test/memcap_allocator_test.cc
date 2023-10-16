//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

// memcap_allocator_test.cc author davis mcpherson <davmcphe@cisco.com>
// unit tests for MemCapAllocator class

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../memcap_allocator.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

const unsigned long ALLOCATION_SIZE = 250;
const unsigned long NO_MEM_CAP_LIMIT = 0;
const unsigned NO_MEMCAP_LIMIT_ALLOCATIONS = 10000;

const unsigned long MEM_CAP_5000 = 5000;
const unsigned MAX_ALLOCATIONS_5000 = MEM_CAP_5000 / ALLOCATION_SIZE;

const unsigned long MEM_CAP_10000 = 10000;
const unsigned MAX_ALLOCATIONS_10000 = MEM_CAP_10000 / ALLOCATION_SIZE;

const unsigned long MEM_CAP_20000 = 20000;
const unsigned MAX_ALLOCATIONS_20000 = MEM_CAP_20000 / ALLOCATION_SIZE;

TEST_GROUP(memcap_allocator)
{ };

TEST(memcap_allocator, no_memcap_limit_allocator_test)
{
    MemCapAllocator* mca = new MemCapAllocator(NO_MEM_CAP_LIMIT, ALLOCATION_SIZE);
    CHECK(mca);
    CHECK(mca->get_allocation_size() == ALLOCATION_SIZE);
    CHECK(mca->get_mem_capacity() == NO_MEM_CAP_LIMIT);
    CHECK(mca->is_space_available());
    CHECK(!mca->is_over_capacity());
    CHECK(mca->get_mem_allocated() == 0);
    CHECK(mca->get_allocation_requests() == 0);
    CHECK(mca->get_free_requests() == 0);
    CHECK(mca->get_no_memory_available() == 0);
    delete mca;
}

TEST(memcap_allocator, no_memcap_limit_allocations_test)
{
    MemCapAllocator* mca = new MemCapAllocator(NO_MEM_CAP_LIMIT, ALLOCATION_SIZE);
    CHECK(mca);

    unsigned bytes_allocated;
    uint8_t** mem_blocks = (uint8_t**)snort_alloc(sizeof(uint8_t*) * NO_MEMCAP_LIMIT_ALLOCATIONS);
    for ( unsigned i = 0; i < NO_MEMCAP_LIMIT_ALLOCATIONS; i++)
    {
        mem_blocks[i] = (uint8_t*)mca->allocate();
        bytes_allocated = (i + 1) * ALLOCATION_SIZE;
        CHECK(mem_blocks[i]);
        CHECK(mca->get_mem_allocated() == bytes_allocated);
        CHECK(mca->is_space_available());
        CHECK(!mca->is_over_capacity());
    }

    CHECK(mca->get_allocation_requests() == NO_MEMCAP_LIMIT_ALLOCATIONS);
    CHECK(mca->get_free_requests() == 0);
    CHECK(mca->get_no_memory_available() == 0);

    for ( unsigned i = 0; i < NO_MEMCAP_LIMIT_ALLOCATIONS; i++)
    {
        mca->free(mem_blocks[i]);
        bytes_allocated = (NO_MEMCAP_LIMIT_ALLOCATIONS - (i + 1)) * ALLOCATION_SIZE;
        CHECK(mca->get_mem_allocated() == bytes_allocated);
    }

    CHECK(mca->is_space_available());
    CHECK(!mca->is_over_capacity());
    CHECK(mca->get_mem_allocated() == 0);
    CHECK(mca->get_free_requests() == NO_MEMCAP_LIMIT_ALLOCATIONS);
    CHECK(mca->get_no_memory_available() == 0);

    snort_free(mem_blocks);
    delete mca;
}

TEST(memcap_allocator, create_memcap_allocator_test)
{
    MemCapAllocator* mca = new MemCapAllocator(MEM_CAP_10000, ALLOCATION_SIZE);
    CHECK(mca);
    CHECK(mca->get_allocation_size() == ALLOCATION_SIZE);
    CHECK(mca->get_mem_capacity() == MEM_CAP_10000);
    mca->set_mem_capacity(MEM_CAP_20000);
    CHECK(mca->get_mem_capacity() == MEM_CAP_20000);
    CHECK(mca->get_mem_allocated() == 0);
    CHECK(mca->get_allocation_requests() == 0);
    CHECK(mca->get_free_requests() == 0);
    CHECK(mca->get_no_memory_available() == 0);
    delete mca;
}

TEST(memcap_allocator, allocate_and_free_memory_test)
{
    MemCapAllocator* mca = new MemCapAllocator(MEM_CAP_10000, ALLOCATION_SIZE);
    CHECK(mca);
    CHECK(mca->is_space_available());
    CHECK(!mca->is_over_capacity());

    uint8_t* mem = (uint8_t*)mca->allocate();
    CHECK(mem);
    CHECK(mca->get_mem_allocated() == ALLOCATION_SIZE);
    CHECK(mca->is_space_available());
    CHECK(!mca->is_over_capacity());
    CHECK(mca->get_allocation_requests() == 1);
    CHECK(mca->get_free_requests() == 0);
    CHECK(mca->get_no_memory_available() == 0);

    mca->free(mem);
    CHECK(mca->get_mem_allocated() == 0);
    CHECK(mca->is_space_available());
    CHECK(!mca->is_over_capacity());
    CHECK(mca->get_allocation_requests() == 1);
    CHECK(mca->get_free_requests() == 1);
    CHECK(mca->get_no_memory_available() == 0);

    delete mca;
}

TEST(memcap_allocator, max_allocations_test)
{
    MemCapAllocator* mca = new MemCapAllocator(MEM_CAP_10000, ALLOCATION_SIZE);
    CHECK(mca);

    unsigned bytes_allocated;
    uint8_t* mem_blocks[MAX_ALLOCATIONS_10000];
    for ( unsigned i = 0; i < MAX_ALLOCATIONS_10000; i++)
    {
        mem_blocks[i] = (uint8_t*)mca->allocate();
        bytes_allocated = (i + 1) * ALLOCATION_SIZE;
        CHECK(mem_blocks[i]);
        CHECK(mca->get_mem_allocated() == bytes_allocated);
        if ( i < MAX_ALLOCATIONS_10000 - 1 )
        {
            CHECK(mca->is_space_available());
        }
        else
        {
            CHECK(!mca->is_space_available());
        }
        CHECK(!mca->is_over_capacity());
    }
    CHECK(mca->get_allocation_requests() == MAX_ALLOCATIONS_10000);
    CHECK(mca->get_free_requests() == 0);
    CHECK(mca->get_no_memory_available() == 0);

    uint8_t* mem = (uint8_t*)mca->allocate();
    CHECK(!mem);
    CHECK(mca->get_no_memory_available() == 1);
    mem = (uint8_t*)mca->allocate();
    CHECK(!mem);
    mem = (uint8_t*)mca->allocate();
    CHECK(!mem);
    CHECK(mca->get_no_memory_available() == 3);
    mca->free(mem_blocks[0]);
    mem_blocks[0] = (uint8_t*)mca->allocate();
    CHECK(mem_blocks[0]);
    CHECK(mca->get_free_requests() == 1);
    CHECK(mca->get_no_memory_available() == 3);

    mca->set_mem_capacity(MEM_CAP_20000);
    mem = (uint8_t*)mca->allocate();
    CHECK(mem);
    mca->set_mem_capacity(MEM_CAP_5000);
    CHECK(mca->is_over_capacity());
    mca->free(mem);
    CHECK(mca->get_free_requests() == 2);

    for ( unsigned i = 0; i < MAX_ALLOCATIONS_5000; i++)
    {
        CHECK(!mca->is_space_available());
        mca->free(mem_blocks[i]);
        bytes_allocated = (MAX_ALLOCATIONS_10000 - (i + 1)) * ALLOCATION_SIZE;
        CHECK(mca->get_mem_allocated() == bytes_allocated);
    }

    CHECK(!mca->is_space_available());
    CHECK(!mca->is_over_capacity());

    for ( unsigned i = MAX_ALLOCATIONS_5000; i < MAX_ALLOCATIONS_10000; i++)
    {
        mca->free(mem_blocks[i]);
        bytes_allocated = (MAX_ALLOCATIONS_10000 - (i + 1)) * ALLOCATION_SIZE;
        CHECK(mca->get_mem_allocated() == bytes_allocated);
        CHECK(mca->is_space_available());
        CHECK(!mca->is_over_capacity());
    }

    CHECK(mca->get_mem_allocated() == 0);
    CHECK(mca->get_free_requests() == MAX_ALLOCATIONS_10000 + 2);
    CHECK(mca->get_no_memory_available() == 3);

    delete mca;
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
