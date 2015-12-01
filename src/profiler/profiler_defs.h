//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
#include "time_profiler_defs.h"
#include "rule_profiler_defs.h"

#define ROOT_NODE "total"

struct ProfilerConfig
{
    TimeProfilerConfig time;
    RuleProfilerConfig rule;
};

struct SO_PUBLIC ProfileStats
{
    TimeProfilerStats time;

    void reset()
    { time.reset(); }

    constexpr ProfileStats() :
        time() { }

    constexpr ProfileStats(TimeProfilerStats time) :
        time(time) { }
};

inline bool operator==(const ProfileStats& lhs, const ProfileStats& rhs)
{ return lhs.time == rhs.time; }

inline bool operator!=(const ProfileStats& lhs, const ProfileStats& rhs)
{ return !(lhs == rhs); }

inline ProfileStats& operator+=(ProfileStats& lhs, const ProfileStats& rhs)
{
    lhs.time += rhs.time;
    return lhs;
}

using get_profile_stats_fn = ProfileStats* (*)(const char*);

struct SO_PUBLIC ProfileContext
{
    TimeContext time;

    void start()
    { time.start(); }

    void pause()
    { time.pause(); }

    ProfileContext(ProfileStats& stats) :
        time(stats.time) { }
};

struct SO_PUBLIC ProfilePause
{
    TimePause time;

    ProfilePause(ProfileContext& ctx) :
        time(ctx.time) { }
};

using Profile = ProfileContext;

#endif
