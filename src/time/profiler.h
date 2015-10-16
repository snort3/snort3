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

// profiler.h author Steven Sturges <ssturges@sourcefire.com>

#ifndef PROFILER_H
#define PROFILER_H

// Facilities for performance profiling

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "main/snort_config.h"

// unconditionally declared
struct ProfileStats
{
    uint64_t ticks;
    uint64_t checks;

    void update(uint64_t elapsed)
    { ++checks; ticks += elapsed; }
};

#include "main/thread.h"
#include "time/cpuclock.h"

// FIXIT-L should go in its own module
class Stopwatch
{
public:
    Stopwatch() :
        elapsed { 0 }, running { false } { }

    void start()
    {
        if ( running )
            return;

        get_clockticks(ticks_start);
        running = true;
    }

    void stop()
    {
        if ( !running )
            return;

        elapsed += get_delta();
        running = false;
    }

    uint64_t get() const
    {
        if ( running )
            return elapsed + get_delta();

        return elapsed;
    }

    bool alive() const
    { return running; }

    void reset()
    { running = false; elapsed = 0; }

    void cancel()
    { running = false; }

private:
    uint64_t get_delta() const
    {
        uint64_t ticks_stop;
        get_clockticks(ticks_stop);
        return ticks_stop - ticks_start;
    }

    uint64_t elapsed;
    bool running;
    uint64_t ticks_start;
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

    uint64_t get_delta() const
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

#ifdef PERF_PROFILING
#ifndef PROFILING_MODULES
#define PROFILING_MODULES SnortConfig::get_profile_modules()
#endif

#ifndef PROFILING_RULES
#define PROFILING_RULES SnortConfig::get_profile_rules()
#endif

#define PERF_PROFILER_NAME(stats) \
    stats ## _perf_profiler

#define PERF_PAUSE_NAME(stats) \
    stats ## _perf_pause

#define PERF_PROFILE(stats) \
    PerfProfiler PERF_PROFILER_NAME(stats) { stats }

#define PERF_PROFILE_BLOCK(stats) \
    if ( PERF_PROFILE(stats) )

#define NODE_PERF_PROFILE(stats) \
    NodePerfProfiler PERF_PROFILER_NAME(stats) { stats }

#define NODE_PERF_PROFILE_BLOCK(stats) \
    if ( NODE_PERF_PROFILE(stats) )

#define NODE_PERF_PROFILE_STOP_MATCH(stats) \
    PERF_PROFILER_NAME(stats) .stop(true)

#define NODE_PERF_PROFILE_STOP_NO_MATCH(stats) \
    PERF_PROFILER_NAME(stats) .stop(false)

#define PERF_PAUSE_BLOCK(stats) \
    if ( ProfilerPause<decltype(PERF_PROFILER_NAME(stats))> \
        PERF_PAUSE_NAME(stats) { PERF_PROFILER_NAME(stats) } )


// thread local access method
using get_profile_func = ProfileStats* (*)(const char*);

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

    static void init();
    static void term();
};

// Sort preferences for rule profiling
#define PROFILE_SORT_CHECKS 1
#define PROFILE_SORT_AVG_TICKS 2
#define PROFILE_SORT_TOTAL_TICKS 3
#define PROFILE_SORT_MATCHES 4
#define PROFILE_SORT_NOMATCHES 5
#define PROFILE_SORT_AVG_TICKS_PER_MATCH 6
#define PROFILE_SORT_AVG_TICKS_PER_NOMATCH 7

// -----------------------------------------------------------------------------
// Profiling API
// -----------------------------------------------------------------------------

struct ProfileConfig
{
    int num;
    int sort;
};

extern THREAD_LOCAL ProfileStats totalPerfStats;
extern THREAD_LOCAL ProfileStats metaPerfStats;

#else
#define PERF_PROFILER_NAME(stats)
#define PERF_PAUSE_NAME(stats)
#define PERF_PROFILE(stats)
#define PERF_PROFILE_BLOCK(stats)
#define NODE_PERF_PROFILE(stats)
#define NODE_PERF_PROFILE_BLOCK(stats)
#define NODE_PERF_PROFILE_STOP_MATCH(stats)
#define NODE_PERF_PROFILE_STOP_NO_MATCH(stats)
#define PERF_PAUSE_BLOCK(stats)

#endif // PERF_PROFILING
#endif

