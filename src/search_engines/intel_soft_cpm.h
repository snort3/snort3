//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

#ifndef INTEL_SOFT_CPM_H
#define INTEL_SOFT_CPM_H

#include <cpa.h>
#include <pm/cpa_pm.h>
#include <cpa_types.h>

#include "main/snort_debug.h"
#include "search_common.h"

struct IntelPmPattern
{
    void* user_data;
    void* rule_option_tree;
    void* neg_list;

    uint8_t* pattern;

    unsigned int pattern_len;
    unsigned int no_case;
    unsigned int negative;

    Cpa32U patternId;
};

struct SnortConfig;

struct IntelPm
{
    Cpa16U patternGroupId;
    Cpa32U patternIds;
    CpaPmSessionCtx sessionCtx;

    void* match_queue;

    /* Temporary data for match callback */
    void* data;
    MpseMatch match;

    const MpseAgent* agent;

    IntelPmPattern* pattern_array;
    Cpa32U pattern_array_len;

    /* Every IntelPm has a reference to this */
    struct _IntelPmHandles* handles;
};

void IntelPmStartInstance();
void IntelPmStopInstance();

void* IntelPmNew(SnortConfig*, const MpseAgent*);

void IntelPmDelete(IntelPm*);

int IntelPmAddPattern(
    SnortConfig* sc,
    IntelPm* ipm,
    const uint8_t* pat,
    unsigned pat_len,
    bool no_case,
    bool negative,
    void* pat_data,
    int pat_id);

int IntelPmFinishGroup(SnortConfig*, IntelPm*);

void IntelPmCompile(SnortConfig*);
void IntelPmActivate(SnortConfig*);
void IntelPmDeactivate();

int IntelPmSearch(IntelPm*, uint8_t* buffer, int buffer_len, MpseMatch, void* context);

int IntelGetPatternCount(IntelPm*);
int IntelPmPrintInfo(IntelPm*);
void IntelPmPrintSummary(SnortConfig*);
void IntelPmPrintBufferStats();
int IntelPmRelease(struct _IntelPmHandles*);

#endif

