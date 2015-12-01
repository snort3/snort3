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
    } sort = Sort::SORT_NONE;

    unsigned count = 0;
    bool show = true;
};

struct SO_PUBLIC TimeProfilerStats
{
    hr_duration elapsed;
    uint64_t checks;

    void update(hr_duration delta)
    { elapsed += delta; ++checks; }

    void reset()
    { elapsed = 0_ticks; checks = 0; }

    operator bool() const
    { return ( elapsed > 0_ticks ) || checks; }

    constexpr TimeProfilerStats() :
        elapsed(0_ticks), checks(0) { }

    constexpr TimeProfilerStats(hr_duration elapsed, uint64_t checks) :
        elapsed(elapsed), checks(checks) { }
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

class TimeContextBase
{
public:
    TimeContextBase() :
        finished(false)
    { start(); }

    void start()
    { sw.start(); }

    void pause()
    { sw.stop(); }

    bool active() const
    { return sw.active(); }

protected:
    Stopwatch sw;
    bool finished;
};

class SO_PUBLIC TimeContext : public TimeContextBase
{
public:
    TimeContext(TimeProfilerStats& stats) :
        TimeContextBase(), stats(stats) { }

    ~TimeContext()
    { stop(); }

    void stop()
    {
        if ( finished )
            return;

        finished = true;
        stats.update(sw.get());
    }

private:
    TimeProfilerStats& stats;
};

class SO_PUBLIC TimePause
{
public:
    TimePause(TimeContextBase& ctx) :
        ctx(ctx)
    { ctx.pause(); }

    ~TimePause()
    { ctx.start(); }

private:
    TimeContextBase& ctx;
};

#endif
