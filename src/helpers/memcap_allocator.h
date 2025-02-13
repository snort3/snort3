//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// memcap_allocator.h author davis mcpherson davmcphe@cisco.com

// MemCapAllocator manages allocation and freeing of fixed size blocks of memory with
// an option of limiting total size of allocations to a specified capacity

#ifndef MEMCAP_ALLOCATOR_H
#define MEMCAP_ALLOCATOR_H

#include "framework/counts.h"
#include "utils/util.h"

class MemCapAllocator
{
public:
    MemCapAllocator(unsigned long capacity, unsigned long allocation_size)
        : mem_capacity(capacity), allocation_size(allocation_size)
    { }

    void* allocate()
    {
        void* data = nullptr;
        if ( is_space_available() )
        {
            data = snort_calloc(allocation_size);
            mem_allocated += allocation_size;
            ++allocation_requests;
        }
        else
            ++no_memory_available;

        return data;
    }

    void free(void* mem)
    {
        snort_free(mem);
        mem_allocated -= allocation_size;
        ++free_requests;
    }

    bool is_space_available() const
    {
        if ( !mem_capacity )
            return true;
        else
            return mem_allocated + allocation_size <= mem_capacity;
    }

    bool is_over_capacity() const
    {
        if ( !mem_capacity )
            return false;
        else
            return mem_allocated > mem_capacity;
    }

    void set_mem_capacity(unsigned long capacity)
    { mem_capacity = capacity; }

    unsigned long get_mem_capacity() const
    { return mem_capacity; }

    unsigned long get_allocation_size() const
    { return allocation_size; }

    unsigned long get_mem_allocated() const
    { return mem_allocated; }

    PegCount get_allocation_requests() const
    { return allocation_requests; }

    PegCount get_free_requests() const
    { return free_requests; }

    PegCount get_no_memory_available() const
    { return no_memory_available; }

private:
    unsigned long mem_capacity;
    unsigned long allocation_size;
    unsigned long mem_allocated = 0;

    PegCount allocation_requests = 0;
    PegCount free_requests = 0;
    PegCount no_memory_available = 0;
};

#endif

