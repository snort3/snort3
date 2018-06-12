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

// memory_defs.h author Joel Cornett <jocornet@cisco.com>

#ifndef MEMORY_DEFS_H
#define MEMORY_DEFS_H

#include "main/thread.h"

struct MemoryStats
{
    uint64_t allocs;
    uint64_t deallocs;
    uint64_t allocated;
    uint64_t deallocated;

    void update_allocs(size_t n)
    { ++allocs; allocated += n; }

    void update_deallocs(size_t n)
    { ++deallocs; deallocated += n; }

    void reset();

    operator bool() const
    { return allocs || allocated; }

    bool operator==(const MemoryStats&) const;
    bool operator!=(const MemoryStats& rhs) const
    { return !(*this == rhs); }

    MemoryStats operator+(const MemoryStats&) const;
    MemoryStats& operator+=(const MemoryStats&);

    constexpr MemoryStats() :
        MemoryStats(0, 0, 0, 0) { }

    constexpr MemoryStats(uint64_t a, uint64_t d, uint64_t ab, uint64_t db) :
        allocs(a), deallocs(d), allocated(ab), deallocated(db) { }
};

inline void MemoryStats::reset()
{
    allocs = 0;
    deallocs = 0;
    allocated = 0;
    deallocated = 0;
}

inline bool MemoryStats::operator==(const MemoryStats& rhs) const
{
    return allocs == rhs.allocs &&
        deallocs == rhs.deallocs &&
        allocated == rhs.allocated &&
        deallocated == rhs.deallocated;
}

inline MemoryStats MemoryStats::operator+(const MemoryStats& rhs) const
{
    return {
        allocs + rhs.allocs,
        deallocs + rhs.deallocs,
        allocated + rhs.allocated,
        deallocated + rhs.deallocated
    };
}

inline MemoryStats& MemoryStats::operator+=(const MemoryStats& rhs)
{
    allocs += rhs.allocs;
    deallocs += rhs.deallocs;
    allocated += rhs.allocated;
    deallocated += rhs.deallocated;

    return *this;
}

struct CombinedMemoryStats
{
    MemoryStats startup;
    MemoryStats runtime;

    void update_allocs(size_t);
    void update_deallocs(size_t);

    void reset();

    operator bool() const
    { return startup || runtime; }

    bool operator==(const CombinedMemoryStats&) const;
    bool operator!=(const CombinedMemoryStats& rhs) const
    { return !(*this == rhs); }

    CombinedMemoryStats& operator+=(const CombinedMemoryStats&);
};

inline void CombinedMemoryStats::update_allocs(size_t n)
{
    if ( snort::is_packet_thread() )
        runtime.update_allocs(n);
    else
        startup.update_allocs(n);
}

inline void CombinedMemoryStats::update_deallocs(size_t n)
{
    if ( snort::is_packet_thread() )
        runtime.update_deallocs(n);
    else
        startup.update_deallocs(n);
}

inline void CombinedMemoryStats::reset()
{
    startup.reset();
    runtime.reset();
}

inline bool CombinedMemoryStats::operator==(const CombinedMemoryStats& rhs) const
{ return startup == rhs.startup && runtime == rhs.runtime; }

inline CombinedMemoryStats& CombinedMemoryStats::operator+=(const CombinedMemoryStats& rhs)
{
    startup += rhs.startup;
    runtime += rhs.runtime;

    return *this;
}

struct MemoryTracker
{
    CombinedMemoryStats stats;

    void reset()
    { stats.reset(); }

    void update_allocs(size_t n)
    { stats.update_allocs(n); }

    void update_deallocs(size_t n)
    { stats.update_deallocs(n); }

    constexpr MemoryTracker() = default;
    constexpr MemoryTracker(const CombinedMemoryStats &stats) : stats(stats) { }
};

#endif
