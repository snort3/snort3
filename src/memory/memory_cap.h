//--------------------------------------------------------------------------
// Copyright (C) 2016-2021 Cisco and/or its affiliates. All rights reserved.
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

// memory_cap.h author Joel Cornett <jocornet@cisco.com>

#ifndef MEMORY_CAP_H
#define MEMORY_CAP_H

#include <cstddef>

#include "framework/counts.h"
#include "main/snort_types.h"

struct MemoryConfig;

namespace memory
{

struct MemoryCounts
{
    PegCount allocations;
    PegCount deallocations;
    PegCount allocated;
    PegCount deallocated;
    PegCount reap_attempts;
    PegCount reap_failures;
    PegCount max_in_use;
};

class SO_PUBLIC MemoryCap
{
public:
    static void setup(const MemoryConfig&, unsigned);
    static void cleanup();

    static void free_space();

    // call from main thread
    static void print(bool verbose, bool print_all = true);

    static MemoryCounts& get_mem_stats();

#ifdef ENABLE_MEMORY_OVERLOADS
    static void allocate(size_t);
    static void deallocate(size_t);
#endif

private:
    static size_t limit;
};

} // namespace memory

#endif
