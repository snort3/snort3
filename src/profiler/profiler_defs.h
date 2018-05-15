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

// profiler_defs.h author Joel Cornett <jocornet@cisco.com>

#ifndef PROFILER_DEFS_H
#define PROFILER_DEFS_H

#include "main/snort_types.h"
#include "memory_defs.h"
#include "memory_profiler_defs.h"
#include "rule_profiler_defs.h"
#include "time_profiler_defs.h"

namespace snort
{
#define ROOT_NODE "total"

struct ProfilerConfig
{
    TimeProfilerConfig time;
    RuleProfilerConfig rule;
    MemoryProfilerConfig memory;
};

struct SO_PUBLIC ProfileStats
{
    TimeProfilerStats time;
    MemoryTracker memory;

    void reset()
    {
        time.reset();
        memory.reset();
    }

    bool operator==(const ProfileStats&) const;
    bool operator!=(const ProfileStats& rhs) const
    { return !(*this == rhs); }

    ProfileStats& operator+=(const ProfileStats&);

    constexpr ProfileStats() = default;
    constexpr ProfileStats(const TimeProfilerStats& time, const MemoryTracker& memory) :
        time(time), memory(memory) { }
};

inline bool ProfileStats::operator==(const ProfileStats& rhs) const
{ return time == rhs.time && memory.stats == rhs.memory.stats; }

inline ProfileStats& ProfileStats::operator+=(const ProfileStats& rhs)
{
    time += rhs.time;
    memory.stats += rhs.memory.stats;

    return *this;
}

class ProfileContext
{
public:
    ProfileContext(ProfileStats& stats) :
        time(stats.time), memory(stats.memory) { }

private:
    TimeContext time;
    MemoryContext memory;
};

class ProfileExclude
{
public:
    ProfileExclude(ProfileStats& stats) : ProfileExclude(stats.time, stats.memory) { }
    ProfileExclude(TimeProfilerStats& time, MemoryTracker&) : time(time) { }

private:
    TimeExclude time;
    MemoryExclude memory;
};

using get_profile_stats_fn = ProfileStats* (*)(const char*);

class NoMemContext
{
public:
    NoMemContext(ProfileStats& stats) :
        time(stats.time) { }

private:
    TimeContext time;
};

class NoMemExclude
{
public:
    NoMemExclude(ProfileStats& stats) : NoMemExclude(stats.time, stats.memory) { }
    NoMemExclude(TimeProfilerStats& time, MemoryTracker&) : time(time) { }

private:
    TimeExclude time;
};

class ProfileDisabled
{
public:
    ProfileDisabled(ProfileStats&) { }
    ProfileDisabled(TimeProfilerStats&, MemoryTracker&) { }
};

#ifdef NO_PROFILER
using Profile = ProfileDisabled;
using DeepProfile = ProfileDisabled;
using NoProfile = ProfileDisabled;
#else
#ifdef NO_MEM_MGR
using Profile = NoMemContext;
using NoProfile = NoMemExclude;
#ifdef DEEP_PROFILING
using DeepProfile = NoMemContext;
#else
using DeepProfile = ProfileDisabled;
#endif
#else
using Profile = ProfileContext;
using NoProfile = ProfileExclude;
#ifdef DEEP_PROFILING
using DeepProfile = ProfileContext;
#else
using DeepProfile = ProfileDisabled;
#endif
#endif
#endif

}
#endif
