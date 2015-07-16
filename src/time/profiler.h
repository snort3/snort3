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
    uint64_t ticks_start;
    uint64_t checks;
    uint64_t exits;
};

#ifdef PERF_PROFILING
#include "main/thread.h"
#include "time/cpuclock.h"

// Sort preferences for rule profiling
#define PROFILE_SORT_CHECKS 1
#define PROFILE_SORT_MATCHES 2
#define PROFILE_SORT_NOMATCHES 3
#define PROFILE_SORT_AVG_TICKS 4
#define PROFILE_SORT_AVG_TICKS_PER_MATCH 5
#define PROFILE_SORT_AVG_TICKS_PER_NOMATCH 6
#define PROFILE_SORT_TOTAL_TICKS 7

// MACROS that handle profiling of rules and preprocessors
#define PROFILE_VARS_NAMED(name) uint64_t name ## _ticks_start, name ## _ticks_end
#define PROFILE_VARS PROFILE_VARS_NAMED(snort)

#define PROFILE_START_NAMED(name) \
    get_clockticks(name ## _ticks_start)

#define PROFILE_END_NAMED(name) \
    get_clockticks(name ## _ticks_end)

#define NODE_PROFILE_END \
    PROFILE_END_NAMED(node); \
    node_ticks_delta = node_ticks_end - node_ticks_start

#ifndef PROFILING_RULES
#define PROFILING_RULES SnortConfig::get_profile_rules()
#endif

#define NODE_PROFILE_VARS \
    uint64_t node_ticks_start = 0, node_ticks_end, node_ticks_delta, node_deltas = 0

#define NODE_PROFILE_START(node) \
    if (PROFILING_RULES) { \
        unsigned id = get_instance_id(); \
        node->state[id].checks++; \
        PROFILE_START_NAMED(node); \
    }

#define NODE_PROFILE_END_MATCH(node) \
    if (PROFILING_RULES) { \
        NODE_PROFILE_END; \
        unsigned id = get_instance_id(); \
        node->state[id].ticks += node_ticks_delta + node_deltas; \
        node->state[id].ticks_match += node_ticks_delta + node_deltas; \
    }

#define NODE_PROFILE_END_NOMATCH(node) \
    if (PROFILING_RULES) { \
        NODE_PROFILE_END; \
        unsigned id = get_instance_id(); \
        node->state[id].ticks += node_ticks_delta + node_deltas; \
        node->state[id].ticks_no_match += node_ticks_delta + node_deltas; \
    }

#define NODE_PROFILE_TMPSTART(node) \
    if (PROFILING_RULES) { \
        PROFILE_START_NAMED(node); \
    }

#define NODE_PROFILE_TMPEND(node) \
    if (PROFILING_RULES) { \
        NODE_PROFILE_END; \
        node_deltas += node_ticks_delta; \
    }

#define OTN_PROFILE_ALERT(otn) otn->state[get_instance_id()].alerts++;

#ifndef PROFILING_MODULES
#define PROFILING_MODULES SnortConfig::get_profile_modules()
#endif

#define MODULE_PROFILE_START_NAMED(name, ppstat) \
    if (PROFILING_MODULES) { \
        ppstat.checks++; \
        PROFILE_START_NAMED(name); \
        ppstat.ticks_start = name ## _ticks_start; \
    }
#define MODULE_PROFILE_START(ppstat) MODULE_PROFILE_START_NAMED(snort, ppstat)

#define MODULE_PROFILE_REENTER_START_NAMED(name, ppstat) \
    if (PROFILING_MODULES) { \
        PROFILE_START_NAMED(name); \
        ppstat.ticks_start = name ## _ticks_start; \
    }
#define MODULE_PROFILE_REENTER_START(ppstat) MODULE_PROFILE_REENTER_START_NAMED(snort, ppstat)

#define MODULE_PROFILE_TMPSTART_NAMED(name, ppstat) \
    if (PROFILING_MODULES) { \
        PROFILE_START_NAMED(name); \
        ppstat.ticks_start = name ## _ticks_start; \
    }
#define MODULE_PROFILE_TMPSTART(ppstat) MODULE_PROFILE_TMPSTART_NAMED(snort, ppstat)

#define MODULE_PROFILE_END_NAMED(name, ppstat) \
    if (PROFILING_MODULES) { \
        PROFILE_END_NAMED(name); \
        ppstat.exits++; \
        ppstat.ticks += name ## _ticks_end - ppstat.ticks_start; \
    }
#define MODULE_PROFILE_END(ppstat) MODULE_PROFILE_END_NAMED(snort, ppstat)

#define MODULE_PROFILE_REENTER_END_NAMED(name, ppstat) \
    if (PROFILING_MODULES) { \
        PROFILE_END_NAMED(name); \
        ppstat.ticks += name ## _ticks_end - ppstat.ticks_start; \
    }
#define MODULE_PROFILE_REENTER_END(ppstat) MODULE_PROFILE_REENTER_END_NAMED(snort, ppstat)

#define MODULE_PROFILE_TMPEND_NAMED(name, ppstat) \
    if (PROFILING_MODULES) { \
        PROFILE_END_NAMED(name); \
        ppstat.ticks += name ## _ticks_end - ppstat.ticks_start; \
    }
#define MODULE_PROFILE_TMPEND(ppstat) MODULE_PROFILE_TMPEND_NAMED(snort, ppstat)


// -----------------------------------------------------------------------------
// Profiling API
// -----------------------------------------------------------------------------

struct ProfileConfig
{
    int num;
    int sort;
};

void ShowRuleProfiles(void);
void ResetRuleProfiling(void);

// thread local access method
using get_profile_func = ProfileStats* (*)(const char*);

void RegisterProfile(
    const char* keyword, const char* parent,
    get_profile_func, class Module* owner = nullptr);

void RegisterProfile(class Module*);

void ShowPreprocProfiles(void);
void ResetPreprocProfiling(void);
void ReleaseProfileStats(void);
void CleanupProfileStatsNodeList(void);

extern THREAD_LOCAL ProfileStats totalPerfStats;
extern THREAD_LOCAL ProfileStats metaPerfStats;
#else
#define PROFILE_VARS
#define PROFILE_VARS_NAMED(name)
#define NODE_PROFILE_VARS
#define NODE_PROFILE_START(node)
#define NODE_PROFILE_END_MATCH(node)
#define NODE_PROFILE_END_NOMATCH(node)
#define NODE_PROFILE_TMPSTART(node)
#define NODE_PROFILE_TMPEND(node)
#define OTN_PROFILE_ALERT(otn)
#define MODULE_PROFILE_START(ppstat)
#define MODULE_PROFILE_START_NAMED(name, ppstat)
#define MODULE_PROFILE_REENTER_START(ppstat)
#define MODULE_PROFILE_REENTER_START_NAMED(name, ppstat)
#define MODULE_PROFILE_TMPSTART(ppstat)
#define MODULE_PROFILE_TMPSTART_NAMED(name, ppstat)
#define MODULE_PROFILE_END(ppstat)
#define MODULE_PROFILE_END_NAMED(name, ppstat)
#define MODULE_PROFILE_REENTER_END(ppstat)
#define MODULE_PROFILE_REENTER_END_NAMED(name, ppstat)
#define MODULE_PROFILE_TMPEND(ppstat)
#define MODULE_PROFILE_TMPEND_NAMED(name, ppstat)
#endif // PERF_PROFILING

static inline void ShowAllProfiles()
{
#ifdef PERF_PROFILING
    ShowPreprocProfiles();
    ShowRuleProfiles();
#endif
}

static inline void ResetAllProfiles()
{
#ifdef PERF_PROFILING
    ResetPreprocProfiling();
    ResetRuleProfiling();
#endif
}

#endif

