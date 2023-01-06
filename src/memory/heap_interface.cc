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

// heap_interface.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "heap_interface.h"

#include <cassert>

#ifdef HAVE_JEMALLOC
#include <jemalloc/jemalloc.h>
#endif

#include "main/thread.h"

namespace memory
{

// -----------------------------------------------------------------------------
#ifdef HAVE_JEMALLOC
// -----------------------------------------------------------------------------

class JemallocInterface : public HeapInterface
{
    void main_init() override;
    void thread_init() override;

    void get_process_total(uint64_t&, uint64_t&) override;
    void get_thread_allocs(uint64_t&, uint64_t&) override;
};

static size_t stats_mib[2], mib_len = 2;

static THREAD_LOCAL uint64_t* alloc_ptr = nullptr;
static THREAD_LOCAL uint64_t* dealloc_ptr = nullptr;

void JemallocInterface::main_init()
{
    mallctlnametomib("stats.allocated", stats_mib, &mib_len);
}

void JemallocInterface::thread_init()
{
    size_t sz = sizeof(alloc_ptr);

    // __STRDUMP_DISABLE__
    mallctl("thread.allocatedp", (void*)&alloc_ptr, &sz, nullptr, 0);
    mallctl("thread.deallocatedp", (void*)&dealloc_ptr, &sz, nullptr, 0);
    // __STRDUMP_ENABLE__
}

void JemallocInterface::get_process_total(uint64_t& epoch, uint64_t& utotal)
{
    uint64_t cycle = 13;
    size_t sz = sizeof(epoch);
    mallctl("epoch", (void*)&epoch, &sz, (void*)&cycle, sizeof(cycle));

    size_t total;
    sz = sizeof(total);
    mallctlbymib(stats_mib, mib_len, (void*)&total, &sz, NULL, 0);

    utotal = total;
}

void JemallocInterface::get_thread_allocs(uint64_t& alloc, uint64_t& dealloc)
{
    assert(alloc_ptr);
    assert(dealloc_ptr);

    alloc = *alloc_ptr;
    dealloc = *dealloc_ptr;
}

//--------------------------------------------------------------------------
#else  // disabled interface
//--------------------------------------------------------------------------

class NerfedInterface : public HeapInterface
{
public:
    void main_init() override { }
    void thread_init() override { }

    void get_process_total(uint64_t& e, uint64_t& t) override
    { e = t = 0; }

    void get_thread_allocs(uint64_t& a, uint64_t& d) override
    { a = d = 0; }
};

#endif

HeapInterface* HeapInterface::get_instance()
{
#ifdef HAVE_JEMALLOC
    return new JemallocInterface;
#else
    return new NerfedInterface;
#endif
}

}  // memory

