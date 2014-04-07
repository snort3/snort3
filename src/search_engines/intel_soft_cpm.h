/****************************************************************************
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ***************************************************************************/

#ifndef INTEL_SOFT_CPM_H
#define INTEL_SOFT_CPM_H

#include "cpa.h"
#include "pm/cpa_pm.h"
#include "cpa_types.h"
#include "snort_debug.h"


/* DATA TYPES *****************************************************************/
typedef struct _IntelPmPattern
{
    void *user_data;
    void *rule_option_tree;
    void *neg_list;

    unsigned char *pattern;
    unsigned int pattern_len;
    unsigned int no_case;
    unsigned int negative;
    int id;   /* pattern id passed in from mpse */
    Cpa32U patternId;  /* actual pattern id */

} IntelPmPattern;

struct SnortConfig;
struct _IntelPmHandles;
typedef struct _IntelPm
{
    Cpa16U patternGroupId;
    Cpa32U patternIds;
    CpaPmSessionCtx sessionCtx;

    /* Temporary data for building trees */
    int (*build_tree)(SnortConfig*, void *id, void **existing_tree);
    int (*neg_list_func)(void *id, void **list);

    void *match_queue;

    /* Temporary data for match callback */
    void *data;
    int (*match)(void *id, void *tree, int index, void *data, void *neg_list);

    void (*user_free)(void *);
    void (*option_tree_free)(void **);
    void (*neg_list_free)(void **);

    IntelPmPattern *pattern_array;
    Cpa32U pattern_array_len;

    /* Every IntelPm has a reference to this */
    struct _IntelPmHandles *handles;

} IntelPm;


/* PROTOTYPES *****************************************************************/
void IntelPmStartInstance(void);
void IntelPmStopInstance(void);

void * IntelPmNew(
    SnortConfig*, 
    void (*user_free)(void *p),
    void (*option_tree_free)(void **p),
    void (*neg_list_free)(void **p));

void IntelPmDelete(IntelPm *ipm);

int IntelPmAddPattern(
    SnortConfig* sc,
    IntelPm *ipm,
    unsigned char *pat,
    int pat_len,
    unsigned no_case,
    unsigned negative,
    void *pat_data,
    int pat_id);

int IntelPmFinishGroup(
    SnortConfig*,
    IntelPm *ipm,
    int (*build_tree)(SnortConfig*, void *id, void **existing_tree),
    int (*neg_list_func)(void *id, void **list));

void IntelPmCompile(SnortConfig*);
void IntelPmActivate(SnortConfig*);
void IntelPmDeactivate(void);

int IntelPmSearch(IntelPm *ipm, unsigned char *buffer, int buffer_len,
        int (*match)(void * id, void *tree, int index, void *data, void *neg_list),
        void *data);

int IntelGetPatternCount(IntelPm *ipm);
int IntelPmPrintInfo(IntelPm *ipm);
void IntelPmPrintSummary(SnortConfig*);
void IntelPmPrintBufferStats(void);

#endif  /* INTEL_SOFT_CPM_H */
