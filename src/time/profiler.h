/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2005-2013 Sourcefire, Inc.
** Author: Steven Sturges <ssturges@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#ifndef PROFILER_H
#define PROFILER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef PERF_PROFILING
#include "thread.h"
#include "time/cpuclock.h"

/* Sort preferences for rule profiling */
#define PROFILE_SORT_CHECKS 1
#define PROFILE_SORT_MATCHES 2
#define PROFILE_SORT_NOMATCHES 3
#define PROFILE_SORT_AVG_TICKS 4
#define PROFILE_SORT_AVG_TICKS_PER_MATCH 5
#define PROFILE_SORT_AVG_TICKS_PER_NOMATCH 6
#define PROFILE_SORT_TOTAL_TICKS 7

/* MACROS that handle profiling of rules and preprocessors */
#define PROFILE_VARS_NAMED(name) uint64_t name##_ticks_start, name##_ticks_end
#define PROFILE_VARS PROFILE_VARS_NAMED(snort)

#define PROFILE_START_NAMED(name) \
    get_clockticks(name##_ticks_start)

#define PROFILE_END_NAMED(name) \
    get_clockticks(name##_ticks_end)

#define NODE_PROFILE_END \
    PROFILE_END_NAMED(node); \
    node_ticks_delta = node_ticks_end - node_ticks_start

#ifndef PROFILING_RULES
#define PROFILING_RULES ScProfileRules()
#endif

#define NODE_PROFILE_VARS uint64_t node_ticks_start, node_ticks_end, node_ticks_delta, node_deltas = 0

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

#ifndef PROFILING_PREPROCS
#define PROFILING_PREPROCS ScProfilePreprocs()
#endif

#define PREPROC_PROFILE_START_NAMED(name, ppstat) \
    if (PROFILING_PREPROCS) { \
        ppstat.checks++; \
        PROFILE_START_NAMED(name); \
        ppstat.ticks_start = name##_ticks_start; \
    }
#define PREPROC_PROFILE_START(ppstat) PREPROC_PROFILE_START_NAMED(snort, ppstat)

#define PREPROC_PROFILE_REENTER_START_NAMED(name, ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_START_NAMED(name); \
        ppstat.ticks_start = name##_ticks_start; \
    }
#define PREPROC_PROFILE_REENTER_START(ppstat) PREPROC_PROFILE_REENTER_START_NAMED(snort, ppstat)

#define PREPROC_PROFILE_TMPSTART_NAMED(name, ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_START_NAMED(name); \
        ppstat.ticks_start = name##_ticks_start; \
    }
#define PREPROC_PROFILE_TMPSTART(ppstat) PREPROC_PROFILE_TMPSTART_NAMED(snort, ppstat)

#define PREPROC_PROFILE_END_NAMED(name, ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END_NAMED(name); \
        ppstat.exits++; \
        ppstat.ticks += name##_ticks_end - ppstat.ticks_start; \
    }
#define PREPROC_PROFILE_END(ppstat) PREPROC_PROFILE_END_NAMED(snort, ppstat)

#define PREPROC_PROFILE_REENTER_END_NAMED(name, ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END_NAMED(name); \
        ppstat.ticks += name##_ticks_end - ppstat.ticks_start; \
    }
#define PREPROC_PROFILE_REENTER_END(ppstat) PREPROC_PROFILE_REENTER_END_NAMED(snort, ppstat)

#define PREPROC_PROFILE_TMPEND_NAMED(name, ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END_NAMED(name); \
        ppstat.ticks += name##_ticks_end - ppstat.ticks_start; \
    }
#define PREPROC_PROFILE_TMPEND(ppstat) PREPROC_PROFILE_TMPEND_NAMED(snort, ppstat)

/************** Profiling API ******************/
void ShowRuleProfiles(void);
void ResetRuleProfiling(void);

/* Preprocessor stats info */
typedef struct _PreprocStats
{
    uint64_t ticks, ticks_start;
    uint64_t checks;
    uint64_t exits;
} PreprocStats;

typedef struct _ProfileConfig
{
    int num;
    int sort;
    int append;
    char *filename;

} ProfileConfig;

// thread local access method
typedef PreprocStats* (*get_profile_func)(const char*);

// FIXIT "preprocessor" here is a misnomer
void RegisterPreprocessorProfile(
    const char* keyword, PreprocStats* stats,
    int layer, PreprocStats* parent, get_profile_func);

void RegisterOtnProfile(
    const char* keyword, PreprocStats* stats, get_profile_func);

void ShowPreprocProfiles(void);
void ResetPreprocProfiling(void);
void ReleasePreprocStats(void);
void CleanupPreprocStatsNodeList(void);

extern THREAD_LOCAL PreprocStats totalPerfStats;
extern THREAD_LOCAL PreprocStats metaPerfStats;
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
#define PREPROC_PROFILE_START(ppstat)
#define PREPROC_PROFILE_START_NAMED(name, ppstat)
#define PREPROC_PROFILE_REENTER_START(ppstat)
#define PREPROC_PROFILE_REENTER_START_NAMED(name, ppstat)
#define PREPROC_PROFILE_TMPSTART(ppstat)
#define PREPROC_PROFILE_TMPSTART_NAMED(name, ppstat)
#define PREPROC_PROFILE_END(ppstat)
#define PREPROC_PROFILE_END_NAMED(name, ppstat)
#define PREPROC_PROFILE_REENTER_END(ppstat)
#define PREPROC_PROFILE_REENTER_END_NAMED(name, ppstat)
#define PREPROC_PROFILE_TMPEND(ppstat)
#define PREPROC_PROFILE_TMPEND_NAMED(name, ppstat)
#endif

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

#endif  /* PROFILER_H */

