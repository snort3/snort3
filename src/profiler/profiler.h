//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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
// profiler.h author Joel Cornett <jocornet@cisco.com>
// based on work by Steven Sturges <ssturges@sourcefire.com>

#ifndef PROFILER_H
#define PROFILER_H

// Facilities for performance profiling

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "main/thread.h"
#include "time/stopwatch.h"

class Module;

enum ProfileSort
{
    PROFILE_SORT_NONE = 0,
    PROFILE_SORT_CHECKS,
    PROFILE_SORT_AVG_TICKS,
    PROFILE_SORT_TOTAL_TICKS,
    PROFILE_SORT_MATCHES,
    PROFILE_SORT_NOMATCHES,
    PROFILE_SORT_AVG_TICKS_PER_MATCH,
    PROFILE_SORT_AVG_TICKS_PER_NOMATCH
};

struct ProfileStats
{
    hr_duration elapsed = 0_ticks;
    uint64_t checks = 0;

    void update(hr_duration delta)
    { ++checks; elapsed += delta; }

    void reset()
    { elapsed = 0_ticks; checks = 0; }

    bool operator==(const ProfileStats& rhs)
    { return elapsed == rhs.elapsed && checks == rhs.checks; }

    operator bool() const
    { return (elapsed > hr_duration::zero()) || checks; }

    ProfileStats& operator+=(const ProfileStats& rhs)
    {
        elapsed += rhs.elapsed;
        checks += rhs.checks;
        return *this;
    }

    ProfileStats() = default;
    ProfileStats(hr_duration elapsed, uint64_t checks) :
        elapsed(elapsed), checks(checks) { }
};

class PerfProfilerBase
{
public:
    PerfProfilerBase()
    { start(); }

    void start()
    { sw.start(); }

    void pause()
    { sw.stop(); }

    // for macro block
    operator bool() const
    { return true; }

    hr_duration get_delta() const
    { return sw.get(); }

private:
    Stopwatch sw;
};

class PerfProfiler : public PerfProfilerBase
{
public:
    PerfProfiler(ProfileStats& ps) :
        PerfProfilerBase(), stats(ps), closed { false } { }

    ~PerfProfiler()
    { stop(); }

    // Once a profiler is stopped, it cannot be restarted
    void stop()
    {
        if ( closed )
            return;

        stats.update(get_delta());
        closed = true;
    }

private:
    ProfileStats& stats;
    bool closed;
};

struct dot_node_state_t;

class NodePerfProfiler : public PerfProfilerBase
{
public:
    NodePerfProfiler(dot_node_state_t& dns) :
        PerfProfilerBase(), stats(dns), closed { false } { }

    // If no stop is explicitly specified, assume no match
    ~NodePerfProfiler()
    { stop(false); }

    void stop(bool match)
    {
        if ( closed )
            return;

        update(match);
        closed = true;
    }

private:
    void update(bool);

    dot_node_state_t& stats;
    bool closed;
};

template<typename Profiler>
struct ProfilerPause
{
    ProfilerPause(Profiler& prof) :
        profiler(prof)
    { profiler.pause(); }

    ~ProfilerPause()
    { profiler.start(); }

    // for macro block
    operator bool() const
    { return true; }

    Profiler& profiler;
};

// thread local access method
using get_profile_func = ProfileStats* (*)(const char*);

#define PERF_PROFILER_NAME(stats) \
    stats ## _perf_profiler

#define PERF_PAUSE_NAME(stats) \
    stats ## _perf_pause

#define PERF_PROFILE(stats) \
    PerfProfiler PERF_PROFILER_NAME(stats) { stats }

#define PERF_PROFILE_THREAD_LOCAL(stats, idx) \
    PerfProfiler PERF_PROFILER_NAME(stats) { stats [ idx ] }

#define PERF_PROFILE_BLOCK(stats) \
    if ( PERF_PROFILE(stats) )

#define PERF_PROFILE_THREAD_LOCAL_BLOCK (stats, idx) \
    if ( PERF_PROFILE_THREAD_LOCAL(stats, idx) )

#define NODE_PERF_PROFILE(stats) \
    NodePerfProfiler PERF_PROFILER_NAME(stats) { stats }

#define NODE_PERF_PROFILE_BLOCK(stats) \
    if ( NODE_PERF_PROFILE(stats) )

#define NODE_PERF_PROFILE_STOP(stats, match) \
    PERF_PROFILER_NAME(stats) .stop(match)

#define NODE_PERF_PROFILE_STOP_MATCH(stats) \
    NODE_PERF_PROFILE_STOP(stats, true)

#define NODE_PERF_PROFILE_STOP_NO_MATCH(stats) \
    NODE_PERF_PROFILE_STOP(stats, false)

#define PERF_PAUSE_BLOCK(stats) \
    if ( ProfilerPause<decltype(PERF_PROFILER_NAME(stats))> \
        PERF_PAUSE_NAME(stats) { PERF_PROFILER_NAME(stats) } )


class PerfProfilerManager
{
public:
    static void register_module(Module*);
    static void register_module(const char*, const char*, Module*);
    static void register_module(const char*, const char*, get_profile_func);

    // thread local
    static void consolidate_stats();

    static void show_module_stats();
    static void reset_module_stats();

    static void show_rule_stats();
    static void reset_rule_stats();

    static void show_all_stats();
    static void reset_all_stats();
};

struct ProfileConfig
{
    int count;
    ProfileSort sort;
};

extern THREAD_LOCAL ProfileStats totalPerfStats;
extern THREAD_LOCAL ProfileStats metaPerfStats;

#endif

