//--------------------------------------------------------------------------
// Copyright (C) 2015-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "main/thread.h"
#include "memory_defs.h"
#include "memory_profiler_defs.h"
#include "rule_profiler_defs.h"
#include "time_profiler_defs.h"

namespace snort
{
#define ROOT_NODE "total"
#define FLEX_NODE "other"

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

class SO_PUBLIC ProfileContext
{
public:
    ProfileContext(ProfileStats& stats) : time(stats.time), memory(stats.memory)
    {
        prev_time = curr_time;
        if ( prev_time )
            prev_time->pause();
        curr_time = &time;
    }

    ~ProfileContext()
    {
        if ( prev_time )
            prev_time->resume();
        curr_time = prev_time;
    }

private:
    TimeContext time;
    MemoryContext memory;
    TimeContext* prev_time;
    static THREAD_LOCAL TimeContext* curr_time;
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

class ProfileDisabled
{
public:
    ProfileDisabled(ProfileStats&) { }
    ProfileDisabled(TimeProfilerStats&, MemoryTracker&) { }
};

#ifdef NO_PROFILER
using Profile = ProfileDisabled;
#else
#ifndef ENABLE_MEMORY_PROFILER
using Profile = NoMemContext;
#else
using Profile = ProfileContext;
#endif
#endif

#ifndef ENABLE_RULE_PROFILER
using RuleProfile = ProfileDisabled;
#else
using RuleProfile = ProfileContext;
#endif

}
#endif
