//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// profiler.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "profiler_impl.h"

#include <cassert>
#include <numeric>

#include "framework/module.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "time/stopwatch.h"
#include "utils/stats.h"

#include "memory_context.h"
#include "memory_profiler.h"
#include "profiler_nodes.h"
#include "rule_profiler.h"
#include "time_profiler.h"
#include <network_inspectors/appid/appid_api.h>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

static THREAD_LOCAL ProfileStats totalPerfStats;
static THREAD_LOCAL ProfileStats otherPerfStats;

THREAD_LOCAL Stopwatch<SnortClock>* run_timer = nullptr;
THREAD_LOCAL uint64_t first_pkt_num = 0;
THREAD_LOCAL bool consolidated_once = false;

static ProfilerNodeMap s_profiler_nodes;

#ifndef _WIN64
THREAD_LOCAL TimeContext* ProfileContext::curr_time = nullptr;
#else
static THREAD_LOCAL TimeContext* curr_time = nullptr;

TimeContext* ProfileContext::get_curr_time()
{ return curr_time; }

void ProfileContext::set_curr_time(TimeContext* t)
{ curr_time = t; }
#endif

ProfileStats* Profiler::get_total_perf_stats()
{ return &totalPerfStats; }

ProfileStats* Profiler::get_other_perf_stats()
{ return &otherPerfStats; }

void Profiler::register_module(Module* m)
{
    if ( m->get_profile() )
        register_module(m->get_name(), nullptr, m);

    else
    {
        unsigned i = 0;
        const char* n, * pn;

        while ( m->get_profile(i++, n, pn) )
            register_module(n, pn, m);
    }
}

void Profiler::register_module(const char* n, const char* pn, Module* m)
{
    assert(n);
    s_profiler_nodes.register_node(n, pn, m);
}

void Profiler::start()
{
    first_pkt_num = pc.analyzed_pkts;
    run_timer = new Stopwatch<SnortClock>;
    run_timer->start();
    consolidated_once = false;
}

void Profiler::stop(uint64_t checks)
{
    if ( run_timer )
    {
        run_timer->stop();
        totalPerfStats.time.elapsed = run_timer->get();
        totalPerfStats.time.checks = checks - first_pkt_num;

        delete run_timer;
        run_timer = nullptr;
    }
}

void Profiler::consolidate_stats(snort::ProfilerType type)
{
    if ( !consolidated_once and type == snort::PROFILER_TYPE_TIME )
    {
        s_profiler_nodes.accumulate_nodes(snort::PROFILER_TYPE_TIME);
        consolidated_once = true;
    }
    else if ( !consolidated_once and type == snort::PROFILER_TYPE_BOTH )
    {
        s_profiler_nodes.accumulate_nodes();
    }

    if ( consolidated_once and type == snort::PROFILER_TYPE_BOTH )
    {
#ifdef ENABLE_MEMORY_PROFILER
        s_profiler_nodes.accumulate_nodes(PROFILER_TYPE_MEMORY);
        MemoryProfiler::consolidate_fallthrough_stats();
#endif
    }
}

void Profiler::reset_stats(snort::ProfilerType type)
{
    if ( type == snort::PROFILER_TYPE_TIME )
    {
        totalPerfStats.reset_time();
        otherPerfStats.reset_time();
    }
    else
    {
        totalPerfStats.reset();
        otherPerfStats.reset();
    }

    s_profiler_nodes.reset_nodes(type);
    appid_api.reset_appid_cpu_profiler_stats();
}

void Profiler::prepare_stats()
{
    const ProfilerNode& root = s_profiler_nodes.get_root();
    auto children = root.get_children();

    hr_duration runtime = root.get_stats().time.elapsed;

    s_profiler_nodes.clear_flex();

    hr_duration sum = std::accumulate(children.cbegin(), children.cend(), 0_ticks,
        [](const hr_duration& s, const ProfilerNode* pn){ return s + pn->get_stats().time.elapsed; });

    otherPerfStats.time.checks = root.get_stats().time.checks;
    otherPerfStats.time.elapsed = (runtime > sum) ?  (runtime - sum) : 0_ticks;

    s_profiler_nodes.accumulate_flex();
}

ProfilerNodeMap& Profiler::get_profiler_nodes()
{
    return s_profiler_nodes;
}

void Profiler::show_stats()
{
    prepare_stats();
    const auto* config = SnortConfig::get_conf()->get_profiler();
    assert(config);

    show_time_profiler_stats(s_profiler_nodes, config->time);
#ifdef ENABLE_MEMORY_PROFILER
    show_memory_profiler_stats(s_profiler_nodes, config->memory);
#endif
    show_rule_profiler_stats(config->rule);
}

void Profiler::show_runtime_memory_stats()
{
    s_profiler_nodes.print_runtime_memory_stats();
}

#ifdef UNIT_TEST

TEST_CASE( "profile stats", "[profiler]" )
{
    SECTION( "ctor" )
    {
        SECTION( "default" )
        {
            ProfileStats stats;

            CHECK( false == stats.time.is_active() );
            CHECK( !stats.memory.stats );
        }

        SECTION( "il" )
        {
            TimeProfilerStats time_stats = { 12_ticks, 2 };
            MemoryTracker memory_stats = {{ 1, 2, 3, 4 }};

            ProfileStats stats(time_stats, memory_stats);

            CHECK( stats.time == time_stats );
            CHECK( stats.memory.stats == memory_stats.stats );
        }
    }

    SECTION( "members" )
    {
        ProfileStats stats {
            { 1_ticks, 2 },
            {{ 1, 2, 3, 4 }}
        };

        SECTION( "reset" )
        {
            stats.reset();

            CHECK( false == stats.time.is_active() );
            CHECK( !stats.memory.stats );
        }

        ProfileStats other_stats {
            { 12_ticks, 12 },
            {{ 5, 6, 7, 8 }}
        };

        SECTION( "==/!=" )
        {
            CHECK( stats == stats );
            CHECK_FALSE( stats == other_stats );
            CHECK( stats != other_stats );
        }

        SECTION( "+=" )
        {
            stats += other_stats;
            CHECK( stats.time == TimeProfilerStats(13_ticks, 14) );
            MemoryStats memory_result = { 6, 8, 10, 12 };

            CHECK( stats.memory.stats == memory_result );
        }
    }
}

#endif
