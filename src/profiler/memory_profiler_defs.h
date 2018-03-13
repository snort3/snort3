//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// memory_profiler_defs.h author Joel Cornett <jocornet@cisco.com>

#ifndef MEMORY_PROFILER_DEFS_H
#define MEMORY_PROFILER_DEFS_H

#include "main/snort_types.h"

struct MemoryTracker;

struct MemoryProfilerConfig
{
    enum Sort
    {
        SORT_NONE,
        SORT_ALLOCATIONS,
        SORT_TOTAL_USED,
        SORT_AVG_ALLOCATION
    } sort = SORT_TOTAL_USED;

    bool show = false;
    unsigned count = 0;
    int max_depth = -1;
};

namespace snort
{
class SO_PUBLIC MemoryContext
{
public:
    MemoryContext(MemoryTracker&);
    ~MemoryContext();

    MemoryContext(const MemoryContext&) = delete;
    MemoryContext& operator=(const MemoryContext&) = delete;

private:
    MemoryTracker* saved;
};

class SO_PUBLIC MemoryExclude
{
public:
    MemoryExclude();
    ~MemoryExclude();

    MemoryExclude(const MemoryExclude&) = delete;
    MemoryExclude& operator=(const MemoryExclude&) = delete;

private:
    MemoryTracker* saved;
};
}
#endif
