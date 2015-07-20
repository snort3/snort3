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
//  Steven Sturges <ssturges@sourcefire.com>

#include "profiler.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mutex>
using namespace std;

#include "detection/fp_detect.h"
#include "detection/treenodes.h"
#include "detection/rules.h"
#include "detection/detection_options.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "main/snort_types.h"
#include "framework/module.h"
#include "hash/sfghash.h"

// FIXIT-M: Instead of using preprocessor directives, use the build system
//          to control compilation of this module
#ifdef PERF_PROFILING

typedef struct _ProfileStatsNode
{
    ProfileStats stats;
    const char* name;
    const char* pname;
    Module* owner;
    int layer;
    struct _ProfileStatsNode* next;
    struct _ProfileStatsNode* parent;
    get_profile_func get_data;
} ProfileStatsNode;

typedef struct _OTN_WorstPerformer
{
    OptTreeNode* otn;
    struct _OTN_WorstPerformer* next;
    struct _OTN_WorstPerformer* prev;
    double ticks_per_check;
    double ticks_per_match;
    double ticks_per_nomatch;
} OTN_WorstPerformer;

typedef struct _Preproc_WorstPerformer
{
    ProfileStatsNode* node;
    struct _Preproc_WorstPerformer* next;
    struct _Preproc_WorstPerformer* prev;
    struct _Preproc_WorstPerformer* children;
    double ticks_per_check;
    double pct_of_parent;
    double pct_of_total;
} Preproc_WorstPerformer;

static THREAD_LOCAL double ticks_per_microsec = 0.0;

static OTN_WorstPerformer* worstPerformers = NULL;
static Preproc_WorstPerformer* worstPreprocPerformers = NULL;

THREAD_LOCAL ProfileStats totalPerfStats;
THREAD_LOCAL ProfileStats metaPerfStats;
static THREAD_LOCAL ProfileStats* mpsePerfStats;

static ProfileStatsNode* gProfileStatsNodeList = NULL;
static int max_layers = 0;

static ProfileStatsNode* get_node(const char*);

#define TOTAL "total"

static ProfileStatsNode* get_root(ProfileStatsNode* idx)
{
    while ( idx->parent )
        idx = idx->parent;
    return idx;
}

static void set_node(ProfileStatsNode* idx)
{
    idx->parent = get_node(idx->pname);

    if ( idx->pname && strcasecmp(idx->pname, TOTAL) )
        idx->layer = idx->parent->layer + 1;
}

static ProfileStatsNode* get_node(const char* s)
{
    for ( ProfileStatsNode* idx = gProfileStatsNodeList; idx; idx = idx->next )
    {
        if ( !strcmp(idx->name, s) )
        {
            if ( idx->pname && !idx->parent )
                set_node(idx);

            return idx;
        }
    }
    return nullptr;
}

static void link_nodes()
{
    for ( ProfileStatsNode* idx = gProfileStatsNodeList; idx; idx = idx->next )
    {
        if ( idx->pname && !idx->parent )
            set_node(idx);

        if ( idx->layer > max_layers)
            max_layers =  idx->layer;
    }
}

static void getTicksPerMicrosec(void)
{
    if (ticks_per_microsec == 0.0)
    {
        ticks_per_microsec = get_ticks_per_usec();
    }
}

void ResetRuleProfiling(void)
{
    /* Cycle through all Rules, print ticks & check count for each */
    RuleTreeNode* rtn;
    SFGHASH_NODE* hashNode;
    OptTreeNode* otn  = NULL;
    SnortConfig* sc = snort_conf;

    if ((sc == NULL) || (sc->profile_rules->num == 0))
        return;

    for (hashNode = sfghash_findfirst(sc->otn_map);
        hashNode;
        hashNode = sfghash_findnext(sc->otn_map))
    {
        otn = (OptTreeNode*)hashNode->data;
        {
            rtn = getRtnFromOtn(otn);
            if (rtn == NULL)
                continue;

            if ( is_network_protocol(rtn->proto) )
            {
                //do operation
                for ( unsigned i = 0; i < get_instance_max(); ++i )
                {
                    OtnState* state = otn->state + i;
                    state->ticks = 0;
                    state->ticks_match = 0;
                    state->ticks_no_match = 0;
                    state->checks = 0;
                    state->matches = 0;
                    state->alerts = 0;
                    state->noalerts = 0;
#ifdef PPM_MGR
                    state->ppm_disable_cnt = 0;
#endif
                }
            }
        }
    }
}

void PrintWorstRules(int numToPrint)
{
    OptTreeNode* otn;
    OTN_WorstPerformer* node, * tmp;
    int num = 0;
    SnortConfig* sc = snort_conf;

    if (sc == NULL)
        return;

    getTicksPerMicrosec();

    if ( !worstPerformers )
        return;

    LogMessage("--------------------------------------------------\n");

    if (numToPrint != -1)
    {
        LogMessage("Rule Profile Statistics (worst %d rules)\n", numToPrint);
    }
    else
    {
        LogMessage("Rule Profile Statistics (all rules)\n");
    }

    LogMessage(
#ifdef PPM_MGR
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#else
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#endif
        6, "Num",
        9, "SID", 4, "GID", 4, "Rev",
        11, "Checks",
        10, "Matches",
        10, "Alerts",
        20, "Microsecs",
        11, "Avg/Check",
        11, "Avg/Match",
        13, "Avg/Nonmatch"
#ifdef PPM_MGR
        , 11, "Disabled"
#endif
        );

    LogMessage(
#ifdef PPM_MGR
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#else
        "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
#endif
        6, "===",
        9, "===", 4, "===", 4, "===",
        11, "======",
        10, "=======",
        10, "======",
        20, "=========",
        11, "=========",
        11, "=========",
        13, "============"
#ifdef PPM_MGR
        , 11, "========"
#endif
        );

    for (node = worstPerformers, num=1;
        node && ((numToPrint < 0) ? 1 : (num <= numToPrint));
        node= node->next, num++)
    {
        //if (!node)
        //    break;
        otn = node->otn;
        OtnState* state = otn->state;

        LogMessage(
#ifdef PPM_MGR
            "%*d%*d%*d%*d" FMTu64("*") FMTu64("*") FMTu64("*") FMTu64(
            "*") "%*.1f%*.1f%*.1f" FMTu64("*") "\n",
#else
            "%*d%*d%*d%*d" FMTu64("*") FMTu64("*") FMTu64("*") FMTu64("*") "%*.1f%*.1f%*.1f" "\n",
#endif
            6, num, 9, otn->sigInfo.id, 4, otn->sigInfo.generator, 4, otn->sigInfo.rev,
            11, state->checks,
            10, state->matches,
            10, state->alerts,
            20, (uint64_t)(state->ticks/ticks_per_microsec),
            11, node->ticks_per_check/ticks_per_microsec,
            11, node->ticks_per_match/ticks_per_microsec,
            13, node->ticks_per_nomatch/ticks_per_microsec
#ifdef PPM_MGR
            , 11, state->ppm_disable_cnt
#endif
            );
    }

    /* Do some cleanup */
    for (node = worstPerformers; node; )
    {
        tmp = node->next;
        free(node);
        node = tmp;
    }

    worstPerformers = NULL;
}

static void sum_otn_profile_data(OtnState* state)
{
    for ( unsigned i = 1; i < get_instance_max(); ++i )
    {
        state[0].ticks += state[i].ticks;
        state[0].ticks_match += state[i].ticks_match;
        state[0].ticks_no_match += state[i].ticks_no_match;
        state[0].checks += state[i].checks;
        state[0].matches += state[i].matches;
        state[0].noalerts += state[i].noalerts;
        state[0].alerts += state[i].alerts;
    }
}

void CollectRTNProfile(void)
{
    OptTreeNode* otn;
    OTN_WorstPerformer* owp, * node, * last = NULL;
    char got_position;
    SFGHASH_NODE* hashNode;
    SnortConfig* sc = snort_conf;

    if (sc == NULL)
        return;

    for (hashNode = sfghash_findfirst(sc->otn_map);
        hashNode;
        hashNode = sfghash_findnext(sc->otn_map))
    {
        otn = (OptTreeNode*)hashNode->data;
        OtnState* state = otn->state;

        sum_otn_profile_data(state);

        {
            /* Only log info if OTN has actually been eval'd */
            if (state->checks > 0 && state->ticks > 0)
            {
                double ticks_per_check = (double)state->ticks/(double)state->checks;
                double ticks_per_nomatch;
                double ticks_per_match;

                if (state->matches > state->checks)
                    state->checks = state->matches;

                if (state->matches)
                    ticks_per_match = (double)state->ticks_match/(double)state->matches;
                else
                    ticks_per_match = 0.0;

                if (state->checks == state->matches)
                    ticks_per_nomatch = 0.0;
                else
                    ticks_per_nomatch = (double)state->ticks_no_match/(double)(state->checks -
                        state->matches);

                /* Find where he goes in the list
                 * Cycle through the list and add
                 * this where it goes
                 */
                owp = (OTN_WorstPerformer*)SnortAlloc(sizeof(OTN_WorstPerformer));
                owp->otn = otn;
                owp->ticks_per_check = ticks_per_check;
                owp->ticks_per_match = ticks_per_match;
                owp->ticks_per_nomatch = ticks_per_nomatch;

                got_position = 0;

                for (node = worstPerformers; node && !got_position; node = node->next)
                {
                    OtnState* worst_otn = node->otn->state;
                    last = node;
                    switch (sc->profile_rules->sort)
                    {
                    case PROFILE_SORT_CHECKS:
                        if (state->checks >= worst_otn->checks)
                        {
                            got_position = 1;
                        }
                        break;
                    case PROFILE_SORT_MATCHES:
                        if (state->matches >= worst_otn->matches)
                        {
                            got_position = 1;
                        }
                        break;
                    case PROFILE_SORT_NOMATCHES:
                        if (state->checks - state->matches >
                            worst_otn->checks - worst_otn->matches)
                        {
                            got_position = 1;
                        }
                        break;
                    case PROFILE_SORT_AVG_TICKS_PER_MATCH:
                        if (ticks_per_match >= node->ticks_per_match)
                        {
                            got_position = 1;
                        }
                        break;
                    case PROFILE_SORT_AVG_TICKS_PER_NOMATCH:
                        if (ticks_per_nomatch >= node->ticks_per_nomatch)
                        {
                            got_position = 1;
                        }
                        break;
                    case PROFILE_SORT_TOTAL_TICKS:
                        if (state->ticks >= worst_otn->ticks)
                        {
                            got_position = 1;
                        }
                        break;
                    default:
                    case PROFILE_SORT_AVG_TICKS:
                        if (ticks_per_check >= node->ticks_per_check)
                        {
                            got_position = 1;
                        }
                        break;
                    }
                    if (got_position)
                        break;
                }

                if (node)
                {
                    owp->next = node;
                    owp->prev = node->prev;
                    node->prev = owp;
                    if (owp->prev)
                        owp->prev->next = owp;
                    /* Reset the head of list */
                    if (node == worstPerformers)
                        worstPerformers = owp;
                }
                else
                {
                    if (!last)
                    {
                        worstPerformers = owp;
                    }
                    else
                    {
                        owp->prev = last;
                        last->next = owp;
                    }
                }
            }
        }
    }
}

void ShowRuleProfiles(void)
{
    /* Cycle through all Rules, print ticks & check count for each */
    SnortConfig* sc = snort_conf;

    if ((sc == NULL) || (sc->profile_rules->num == 0))
        return;

    detection_option_tree_update_otn_stats(sc->detection_option_tree_hash_table);

    CollectRTNProfile();
    link_nodes();

    /* Specifically call out a top xxx or something? */
    PrintWorstRules(sc->profile_rules->num);
}

/* The preprocessor profile list is only accessed for printing stats when
 * Snort shuts down. */
void RegisterProfile(
    const char* keyword, const char* parent, get_profile_func get, Module* mod)
{
    ProfileStatsNode* node;
    node = (ProfileStatsNode*)SnortAlloc(sizeof(ProfileStatsNode));

    if (gProfileStatsNodeList == NULL)
    {
        gProfileStatsNodeList = node;
    }
    else
    {
        ProfileStatsNode* tmp = gProfileStatsNodeList;
        ProfileStatsNode* last;

        do
        {
            if (strcasecmp(tmp->name, keyword) == 0)
            {
                //FatalError("Duplicate Preprocessor Stats Name (%s)\n", keyword);
                /* Don't fatal error here since during a reload there are
                 * probably going to be dups - just return */
                //multiple policy support
                free(node);
                return;
            }

            last = tmp;
            tmp = tmp->next;
        }
        while (tmp != NULL);

        last->next = node;
    }

    node->name = keyword;
    node->pname = parent;
    node->layer = 0;
    node->get_data = get;
    node->owner = mod;
    node->parent = nullptr;

    if ( !node->pname && strcasecmp(node->name, TOTAL) )
        node->pname = TOTAL;

    if ( !strcasecmp(node->name, "mpse") )
        mpsePerfStats = &node->stats;
}

void RegisterProfile(Module* m)
{
    ProfileStats* ps = m->get_profile();

    if ( ps )
        RegisterProfile(m->get_name(), nullptr, nullptr, m);

    else
    {
        unsigned i = 0;
        const char* name, * pname;

        while ( (ps = m->get_profile(i++, name, pname)) )
            RegisterProfile(name, pname, nullptr, m);
    }
}

static ProfileStats* get_profile(ProfileStatsNode* node)
{
    ProfileStats* ps = node->owner->get_profile();

    if ( ps )
        return ps;

    unsigned i = 0;
    const char* name, * pname;

    while ( (ps = node->owner->get_profile(i++, name, pname)) &&
        strcasecmp(node->name, name) )
        ;

    return ps;
}

void FreePreprocPerformance(Preproc_WorstPerformer* idx)
{
    Preproc_WorstPerformer* child, * tmp;
    child = idx->children;
    while (child)
    {
        FreePreprocPerformance(child);
        tmp = child;
        child = child->next;
        free(tmp);
    }
}

void PrintPreprocPerformance(int num, Preproc_WorstPerformer* idx)
{
    Preproc_WorstPerformer* child;
    int i;
    /* indent 'Num' based on the layer */
    unsigned int indent = 6 - (5 - idx->node->layer);

    if (num != 0)
    {
        indent += 2;
        LogMessage("%*d%*s%*d" FMTu64("*") FMTu64("*") FMTu64("*") "%*.2f%*.2f%*.2f\n",
            indent, num,
            28 - indent, idx->node->name, 6, idx->node->layer,
            11, idx->node->stats.checks,
            11, idx->node->stats.exits,
            20, (uint64_t)(idx->node->stats.ticks/ticks_per_microsec),
            11, idx->ticks_per_check/ticks_per_microsec,
            14, idx->pct_of_parent,
            13, idx->pct_of_total);
    }
    else
    {
        /* The totals */
        indent += strlen(idx->node->name);

        LogMessage("%*s%*s%*d" FMTu64("*") FMTu64("*") FMTu64("*") "%*.2f%*.2f%*.2f\n",
            indent, idx->node->name,
            28 - indent, idx->node->name, 6, idx->node->layer,
            11, idx->node->stats.checks,
            11, idx->node->stats.exits,
            20, (uint64_t)(idx->node->stats.ticks/ticks_per_microsec),
            11, idx->ticks_per_check/ticks_per_microsec,
            14, idx->pct_of_parent,
            13, idx->pct_of_parent);
    }

    child = idx->children;

    i = 1;
    while (child)
    {
        PrintPreprocPerformance(i++, child);
        child = child->next;
    }
}

// from main thread only
static void CleanupProfileStatsNodeList(ProfileStatsNode* node)
{
    while (node)
    {
        ProfileStatsNode* nxt = node->next;
        free(node);
        node = nxt;
    }
}

// from main thread only
void CleanupProfileStatsNodeList(void)
{
    CleanupProfileStatsNodeList(gProfileStatsNodeList);
    gProfileStatsNodeList = NULL;
}

// from packet thread only
void ReleaseProfileStats(void)
{
    static mutex stats_mutex;
    stats_mutex.lock();

    ProfileStatsNode* node = gProfileStatsNodeList;

    while (node)
    {
        const ProfileStats* ps;
        assert(node->get_data || node->owner);

        if ( node->owner )
            ps = get_profile(node);
        else
            ps = node->get_data(node->name);
        assert(ps);

        node->stats.ticks += ps->ticks;
        node->stats.ticks_start += ps->ticks_start;
        node->stats.checks += ps->checks;
        node->stats.exits += ps->exits;

        node = node->next;
    }
    stats_mutex.unlock();
}

void CleanupPreprocPerformance(Preproc_WorstPerformer* worst)
{
    Preproc_WorstPerformer* idx, * child, * tmp;

    idx = worst;
    while (idx)
    {
        tmp = idx->next;
        child = idx->children;
        CleanupPreprocPerformance(child);

        free(idx);
        idx = tmp;
    }
}

void PrintWorstPreprocs(int numToPrint)
{
    Preproc_WorstPerformer* idx;
    Preproc_WorstPerformer* total = NULL;
    int num = 0;

    getTicksPerMicrosec();

    if ( !worstPreprocPerformers )
        return;

    LogMessage("--------------------------------------------------\n");

    if (numToPrint != -1)
        LogMessage("Module Profile Statistics (worst %d)\n", numToPrint);
    else
        LogMessage("Module Profile Statistics (all)\n");

    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
        4, "Num",
        24, "Module",
        6, "Layer",
        11, "Checks",
        11, "Exits",
        20, "Microsecs",
        11, "Avg/Check",
        14, "Pct of Caller",
        13, "Pct of Total");

    LogMessage("%*s%*s%*s%*s%*s%*s%*s%*s%*s\n",
        4, "===",
        24, "======",
        6, "=====",
        11, "======",
        11, "=====",
        20, "=========",
        11, "=========",
        14, "=============",
        13, "============");

    for (idx = worstPreprocPerformers, num=1;
        idx && ((numToPrint < 0) ? 1 : (num <= numToPrint));
        idx= idx->next, num++)
    {
        /* Skip the total counter */
        if ( !strcasecmp(idx->node->name, TOTAL) )
        {
            num--;
            total = idx;
            continue;
        }
        PrintPreprocPerformance(num, idx);
    }
    if (total)
        PrintPreprocPerformance(0, total);

    CleanupPreprocPerformance(worstPreprocPerformers);
    worstPreprocPerformers = NULL;
}

Preproc_WorstPerformer* findPerfParent(ProfileStatsNode* node,
    Preproc_WorstPerformer* top)
{
    Preproc_WorstPerformer* list = top;
    Preproc_WorstPerformer* parent;

    if (!list)
        return NULL;

    if (list->node->layer > node->layer)
        return NULL;

    while (list)
    {
        if ( !strcmp(list->node->name, node->pname) )
            return list;

        parent = findPerfParent(node, list->children);

        if (parent)
            return parent;

        list = list->next;
    }

    return NULL;
}

void ResetPreprocProfiling(void)
{
    ProfileStatsNode* idx = NULL;
    SnortConfig* sc = snort_conf;

    if ((sc == NULL) || (sc->profile_modules->num == 0))
        return;

    for (idx = gProfileStatsNodeList; idx != NULL; idx = idx->next)
    {
        idx->stats.ticks = 0;
        idx->stats.ticks_start = 0;
        idx->stats.checks = 0;
        idx->stats.exits = 0;
    }
}

void ShowPreprocProfiles(void)
{
    /* Cycle through all Rules, print ticks & check count for each */
    ProfileStatsNode* idx;
    int layer;
    Preproc_WorstPerformer* parent, * pwp, * curr = NULL, * last = NULL;
    char got_position;
    Preproc_WorstPerformer* listhead;
    double ticks_per_check;
    SnortConfig* sc = snort_conf;

    if ((sc == NULL) || (sc->profile_modules->num == 0))
        return;

    link_nodes();

    /* Adjust mpse stats to not include rule evaluation */
    if ( mpsePerfStats )
        mpsePerfStats->ticks -= rulePerfStats.ticks;

    /* And adjust the rules to include the NC rules */
    rulePerfStats.ticks += ncrulePerfStats.ticks;

    for (layer=0; layer<=max_layers; layer++)
    {
        for (idx = gProfileStatsNodeList; idx; idx = idx->next)
        {
            if (idx->stats.checks == 0 || idx->stats.ticks == 0)
                continue;

            if (idx->layer != layer)
                continue;

            last = NULL;

            ticks_per_check = (double)idx->stats.ticks/(double)idx->stats.checks;

            pwp = (Preproc_WorstPerformer*)SnortAlloc(sizeof(Preproc_WorstPerformer));
            pwp->node = idx;
            pwp->ticks_per_check = ticks_per_check;

            if (idx->parent)
            {
                /* Find this idx's parent in the list */
                parent = findPerfParent(idx, worstPreprocPerformers);
                if (parent && strcasecmp(parent->node->name, TOTAL))
                {
                    listhead = parent->children;
                }
                else
                {
                    listhead = worstPreprocPerformers;
                    parent = NULL;
                }
                pwp->pct_of_parent = (double)idx->stats.ticks/idx->parent->stats.ticks*100.0;
                pwp->pct_of_total = (double)idx->stats.ticks/get_root(idx)->stats.ticks*100.0;
            }
            else
            {
                parent = NULL;
                pwp->pct_of_parent = 0.0;
                pwp->pct_of_total = 100.0;
                listhead = worstPreprocPerformers;
            }

            got_position = 0;

            for (curr = listhead; curr && !got_position; curr = curr->next)
            {
                last = curr;
                switch (sc->profile_modules->sort)
                {
                case PROFILE_SORT_CHECKS:
                    if (pwp->node->stats.checks >= curr->node->stats.checks)
                    {
                        got_position = 1;
                    }
                    break;
                case PROFILE_SORT_TOTAL_TICKS:
                    if (pwp->node->stats.ticks >= curr->node->stats.ticks)
                    {
                        got_position = 1;
                    }
                    break;
                default:
                case PROFILE_SORT_AVG_TICKS:
                    if (pwp->ticks_per_check >= curr->ticks_per_check)
                    {
                        got_position = 1;
                    }
                    break;
                }
                if (got_position)
                    break;
            }
            if (curr)
            {
                pwp->next = curr;
                pwp->prev = curr->prev;
                curr->prev = pwp;
                if (pwp->prev)
                    pwp->prev->next = pwp;
                /* Reset the head of the list */
                if (curr == listhead)
                {
                    if (parent)
                    {
                        parent->children = pwp;
                    }
                    else
                    {
                        worstPreprocPerformers = pwp;
                    }
                }
            }
            else
            {
                if (!last)
                {
                    if (parent)
                    {
                        parent->children = pwp;
                    }
                    else
                    {
                        worstPreprocPerformers = pwp;
                    }
                }
                else
                {
                    pwp->prev = last;
                    last->next = pwp;
                }
            }
        }
    }
    PrintWorstPreprocs(sc->profile_modules->num);
    CleanupProfileStatsNodeList();
}

#endif

