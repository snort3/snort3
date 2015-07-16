//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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
// ppm.h author Marc Norton <mnorton@sourcefire.com>

#ifndef PPM_H
#define PPM_H

// Provide facilities for packet performance monitoring

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// FIXIT-M: Instead of an empty source file, use CMake/Make to enable/disable
//          this compilation unit
#ifdef PPM_MGR
#include "main/snort_types.h"
#include "main/thread.h"
#include "time/cpuclock.h"
#include "detection/detection_options.h"

#define cputime get_clockticks

typedef uint64_t PPM_TICKS;
typedef uint64_t PPM_USECS;
typedef unsigned int PPM_SECS;

struct ppm_cfg_t
{
    // config section
    int enabled;

    PPM_TICKS max_pkt_ticks;
    int pkt_log;     // alert,console,syslog
    int pkt_action;  // suspend

    PPM_TICKS max_rule_ticks;
    uint64_t rule_threshold; // rules must fail this many times in a row to suspend

    int rule_log;    // alert,console,syslog
    int rule_action; // suspend

    uint64_t max_suspend_ticks;
};

struct ppm_stats_t
{
    // stats section
    unsigned int rule_event_cnt;
    unsigned int pkt_event_cnt;

    uint64_t tot_pkt_time;   // ticks
    uint64_t tot_pkts;

    uint64_t tot_rule_time;   // ticks
    uint64_t tot_rules;

    uint64_t tot_nc_rule_time;   // ticks
    uint64_t tot_nc_rules;

    uint64_t tot_pcre_rule_time;   // ticks
    uint64_t tot_pcre_rules;
};

extern THREAD_LOCAL ppm_stats_t ppm_stats;

typedef struct
{
    uint64_t pktcnt;
    uint64_t start, cur, tot;
    uint64_t subtract;
    PPM_TICKS max_pkt_ticks;
    unsigned int rule_tests;
    unsigned int pcre_rule_tests;
    unsigned int nc_rule_tests;
} ppm_pkt_timer_t;

typedef struct
{
    uint64_t start, cur, tot;
    PPM_TICKS max_rule_ticks;
} ppm_rule_timer_t;

// global data
#define PPM_MAX_TIMERS 10
extern PPM_TICKS ppm_tpu;
extern THREAD_LOCAL ppm_pkt_timer_t ppm_pkt_times[PPM_MAX_TIMERS];
extern THREAD_LOCAL ppm_pkt_timer_t* ppm_pt;
extern THREAD_LOCAL unsigned int ppm_pkt_index;
extern THREAD_LOCAL ppm_rule_timer_t ppm_rule_times[PPM_MAX_TIMERS];
extern THREAD_LOCAL ppm_rule_timer_t* ppm_rt;
extern THREAD_LOCAL unsigned int ppm_rule_times_index;
extern THREAD_LOCAL uint64_t ppm_cur_time;
extern THREAD_LOCAL int ppm_abort_this_pkt;
extern THREAD_LOCAL int ppm_suspend_this_rule;

#define PPM_LOG_ALERT      1
#define PPM_LOG_MESSAGE    2
#define PPM_ACTION_SUSPEND 1

// config flags
#define PPM_ENABLED()                 (snort_conf->ppm_cfg->enabled > 0)
#define PPM_PKTS_ENABLED()            (snort_conf->ppm_cfg->max_pkt_ticks > 0)
#define PPM_RULES_ENABLED()           (snort_conf->ppm_cfg->max_rule_ticks > 0)

// packet, rule event flags
#define PPM_PACKET_ABORT_FLAG()       ppm_abort_this_pkt
#define PPM_RULE_SUSPEND_FLAG()       ppm_suspend_this_rule

#define PPM_INC_PKT_CNT()         ppm_stats.tot_pkts++
#define PPM_PKT_CNT()             ppm_pt->pktcnt
#define PPM_PKT_LOG(p)            if (ppm_abort_this_pkt) ppm_pkt_log(snort_conf->ppm_cfg,p)
#define PPM_RULE_LOG(cnt,p)       ppm_rule_log(snort_conf->ppm_cfg,cnt,p)
#define PPM_ACCUM_PKT_TIME() \
    if ( ppm_pt ) \
    { \
        ppm_stats.tot_pkt_time += ppm_pt->tot; \
    }
#define PPM_ACCUM_RULE_TIME() \
    if ( ppm_rt ) \
    { \
        ppm_stats.tot_rule_time += ppm_rt->tot; \
        ppm_stats.tot_rules++; \
    }
#define PPM_ACCUM_NC_RULE_TIME() \
    ppm_stats.tot_nc_rule_time += ppm_rt->tot; \
    ppm_stats.tot_nc_rules++;
#define PPM_ACCUM_PCRE_RULE_TIME() \
    ppm_stats.tot_pcre_rule_time += ppm_rt->tot; \
    ppm_stats.tot_pcre_rules++;
#define PPM_GET_TIME()             cputime(ppm_cur_time)
#define PPM_PKT_RULE_TESTS()       ppm_pt->rule_tests
#define PPM_PKT_PCRE_RULE_TESTS()  ppm_pt->pcre_rule_tests
#define PPM_PKT_NC_RULE_TESTS()    ppm_pt->nc_rule_tests
#define PPM_INC_PKT_RULE_TESTS()      if (ppm_pt) ppm_pt->rule_tests++
#define PPM_INC_PKT_PCRE_RULE_TESTS() if (ppm_pt) ppm_pt->pcre_rule_tests++
#define PPM_INC_PKT_NC_RULE_TESTS()   if (ppm_pt) ppm_pt->nc_rule_tests++

#define PPM_PRINT_PKT_TIME(a)    LogMessage(a, ppm_ticks_to_usecs((PPM_TICKS)ppm_pt->tot) );

#ifdef PPM_TEST
// use usecs instead of ticks for rule suspension during pcap playback
#define PPM_RULE_TIME(p) ((p->pkth->ts.tv_sec * 1000000) + p->pkth->ts.tv_usec)
#else
#define PPM_RULE_TIME(p) ppm_cur_time
#endif

#define PPM_INIT_PKT_TIMER() \
    if (ppm_pkt_index < PPM_MAX_TIMERS) \
    { \
        ppm_pt = &ppm_pkt_times[ppm_pkt_index++]; \
        ppm_abort_this_pkt = 0; \
        ppm_pt->pktcnt = ppm_stats.tot_pkts; \
        ppm_pt->start = ppm_cur_time; \
        ppm_pt->subtract = 0; \
        ppm_pt->rule_tests = 0; \
        ppm_pt->pcre_rule_tests = 0; \
        ppm_pt->nc_rule_tests = 0; \
        ppm_pt->max_pkt_ticks = snort_conf->ppm_cfg->max_pkt_ticks; \
        ppm_init_rules(); \
    }

#define PPM_TOTAL_PKT_TIME() \
    if ( ppm_pt) \
    { \
        ppm_pt->tot = ppm_cur_time - ppm_pt->start - ppm_pt->subtract; \
    }

#define PPM_END_PKT_TIMER() \
    if ( (ppm_pkt_index > 0)  && ppm_pt) \
    { \
        ppm_pkt_index--; \
        if ( ppm_pkt_index > 0 ) \
            ppm_pt = &ppm_pkt_times[ppm_pkt_index-1]; \
        else \
            ppm_pt=0; \
    }

#define PPM_INIT_RULE_TIMER() \
    if (ppm_rule_times_index < PPM_MAX_TIMERS) \
    { \
        ppm_rt = &ppm_rule_times[ppm_rule_times_index++]; \
        ppm_suspend_this_rule = 0; \
        ppm_rt->start=ppm_cur_time; \
        ppm_rt->max_rule_ticks = snort_conf->ppm_cfg->max_rule_ticks; \
    }

#define PPM_END_RULE_TIMER() \
    if (( ppm_rule_times_index > 0) && ppm_rt ) \
    { \
        ppm_rule_times_index--; \
        if (ppm_rule_times_index > 0) \
        { \
            ppm_rt=&ppm_rule_times[ppm_rule_times_index-1]; \
        } else { \
            ppm_rt=NULL; \
        } \
    }

// use PPM_GET_TIME; first to get the current time
#define PPM_PACKET_TEST() \
    if ( ppm_pt ) \
    { \
        ppm_pt->tot = ppm_cur_time - ppm_pt->start; \
        if (ppm_pt->tot > ppm_pt->max_pkt_ticks) \
        { \
            if ( snort_conf->ppm_cfg->pkt_action & PPM_ACTION_SUSPEND ) \
                ppm_abort_this_pkt = 1; \
        } \
    }

#if 0 && defined(PPM_TEST)
#define PPM_DBG_CSV(state, otn, when) \
    LogMessage( \
    "PPM, %u, %u, %s, " STDu64 "\n", \
    otn->sigInfo.generator, otn->sigInfo.id, state, when \
    )
#else
#define PPM_DBG_CSV(state, otn, when)
#endif

// use PPM_GET_TIME; first to get the current time
#define PPM_RULE_TEST(root,p) \
    if ( ppm_rt ) \
    { \
        ppm_rt->tot = ppm_cur_time - ppm_rt->start; \
        if (ppm_rt->tot > ppm_rt->max_rule_ticks) \
        { \
            dot_root_state_t* root_state = (root)->state + get_instance_id(); \
            if ( snort_conf->ppm_cfg->rule_action & PPM_ACTION_SUSPEND ) \
            { \
                int ii; \
                ppm_suspend_this_rule = 1; \
                (root_state)->ppm_disable_cnt++; \
                for ( ii = 0; ii< root->num_children; ii++) \
                { \
                    dot_node_state_t* ns = \
                        root->children[ii]->state + get_instance_id(); \
                    ns->ppm_disable_cnt++; \
                } \
                if ( (root_state)->ppm_disable_cnt >= snort_conf->ppm_cfg->rule_threshold ) \
                { \
                    ppm_set_rule_event(snort_conf->ppm_cfg, root); \
                    (root_state)->enabled=false; \
                    (root_state)->ppm_suspend_time=PPM_RULE_TIME(p); \
                    PPM_DBG_CSV("disabled", (root), (root)->ppm_suspend_time); \
                } \
                else \
                { \
                    (root_state)->ppm_suspend_time=0; \
                } \
            } \
            else \
            { \
                (root_state)->ppm_suspend_time=0; \
                if ( (root_state)->ppm_disable_cnt > 0 ) \
                    (root_state)->ppm_disable_cnt--; \
            } \
        } \
    }

#define PPM_REENABLE_TREE(root,p) \
    dot_root_state_t* root_state = (root)->state + get_instance_id(); \
    if ( (root_state)->ppm_suspend_time && snort_conf->ppm_cfg->max_suspend_ticks ) \
    { \
        PPM_TICKS now = PPM_RULE_TIME(p); \
        PPM_TICKS then = (root_state)->ppm_suspend_time + snort_conf->ppm_cfg->max_suspend_ticks; \
        if ( now > then ) \
        { \
            (root_state)->ppm_suspend_time=0; \
            (root_state)->enabled=true; \
            ppm_clear_rule_event(snort_conf->ppm_cfg, root); \
            PPM_DBG_CSV("enabled", (root), now); \
        } \
        else \
        { \
            PPM_DBG_CSV("pending", (root), then-now); \
        } \
    }

void ppm_init(ppm_cfg_t*);

void ppm_set_pkt_action(ppm_cfg_t*, int);
void ppm_set_pkt_log(ppm_cfg_t*, int);

void ppm_set_rule_action(ppm_cfg_t*, int);
void ppm_set_rule_threshold(ppm_cfg_t*, unsigned int);
void ppm_set_rule_log(ppm_cfg_t*, int);

void ppm_set_max_pkt_time(ppm_cfg_t*, PPM_USECS);
void ppm_set_max_rule_time(ppm_cfg_t*, PPM_USECS);
void ppm_set_max_suspend_time(ppm_cfg_t*, PPM_SECS);

void ppm_print_cfg(ppm_cfg_t*);
void ppm_print_summary(ppm_cfg_t*);
void ppm_sum_stats();
double ppm_ticks_to_usecs(PPM_TICKS);

void ppm_pkt_log(ppm_cfg_t*, Packet*);
void ppm_rule_log(ppm_cfg_t*, uint64_t, Packet*);

void ppm_init_rules(void);
void ppm_set_rule_event(ppm_cfg_t*, detection_option_tree_root_t*);
void ppm_clear_rule_event(ppm_cfg_t*, detection_option_tree_root_t*);
void ppm_set_rule(detection_option_tree_root_t*, PPM_TICKS);

#define PPM_INIT(x)           ppm_init(x)
#define PPM_PRINT_CFG(x)      ppm_print_cfg(x)
#define PPM_PRINT_SUMMARY(x)  ppm_print_summary(x)

#else

#define PPM_GET_TIME()
#define PPM_SET_TIME()

#endif // PPM_MGR

#endif

