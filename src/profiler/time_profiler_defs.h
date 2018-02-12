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

// time_profiler_defs.h author Joel Cornett <jocornet@cisco.com>

#ifndef TIME_PROFILER_DEFS_H
#define TIME_PROFILER_DEFS_H

#include "main/snort_types.h"
#include "time/clock_defs.h"
#include "time/stopwatch.h"

struct TimeProfilerConfig
{
    enum Sort
    {
        SORT_NONE = 0,
        SORT_CHECKS,
        SORT_AVG_CHECK,
        SORT_TOTAL_TIME
    } sort = SORT_TOTAL_TIME;

    bool show = false;
    unsigned count = 0;
    int max_depth = -1;
};

struct SO_PUBLIC TimeProfilerStats
{
    hr_duration elapsed;
    uint64_t checks;
    mutable unsigned int ref_count;

    void update(hr_duration delta)
    { elapsed += delta; ++checks; }

    void reset()
    { elapsed = 0_ticks; checks = 0; }

    operator bool() const
    { return ( elapsed > 0_ticks ) || checks; }

    // reentrancy control
    bool enter() const { return ref_count++ == 0; }
    bool exit() const { return --ref_count == 0; }

    constexpr TimeProfilerStats() :
        TimeProfilerStats(0_ticks, 0, 0) { }

    constexpr TimeProfilerStats(hr_duration elapsed, uint64_t checks) :
        TimeProfilerStats(elapsed, checks, 0) { }

    constexpr TimeProfilerStats(hr_duration elapsed, uint64_t checks, unsigned int ref_count) :
        elapsed(elapsed), checks(checks), ref_count(ref_count) { }
};

inline bool operator==(const TimeProfilerStats& lhs, const TimeProfilerStats& rhs)
{ return (lhs.elapsed == rhs.elapsed) && (lhs.checks == rhs.checks); }

inline bool operator!=(const TimeProfilerStats& lhs, const TimeProfilerStats& rhs)
{ return !(lhs == rhs); }

inline TimeProfilerStats& operator+=(TimeProfilerStats& lhs, const TimeProfilerStats& rhs)
{
    lhs.elapsed += rhs.elapsed;
    lhs.checks += rhs.checks;
    return lhs;
}

class TimeContext
{
public:
    TimeContext(TimeProfilerStats& stats) :
        stats(stats)
    {
        if ( stats.enter() )
            sw.start();
    }

    ~TimeContext()
    { stop(); }

    // Use this for finer grained control of the TimeContext "lifetime"
    void stop()
    {
        if ( stopped_once )
            return; // stop() should only be executed once per context

        stopped_once = true;

        // don't bother updating time if context is reentrant
        if ( stats.exit() )
            stats.update(sw.get());
    }

    bool active() const
    { return !stopped_once; }

private:
    TimeProfilerStats& stats;
    Stopwatch<SnortClock> sw;
    bool stopped_once = false;
};

class TimeExclude
{
public:
    TimeExclude(TimeProfilerStats& stats) :
        stats(stats), ctx(tmp) { }

    TimeExclude(const TimeExclude&) = delete;
    TimeExclude& operator=(const TimeExclude&) = delete;

    ~TimeExclude()
    {
        ctx.stop();
        stats.elapsed -= tmp.elapsed;
    }

private:
    TimeProfilerStats& stats;
    TimeProfilerStats tmp;
    TimeContext ctx;
};

#endif
