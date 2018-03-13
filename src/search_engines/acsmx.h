//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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

// acsmx.h author Marc Norton

#ifndef ACSMX_H
#define ACSMX_H

// version 1

#include <cstdint>

#include "search_common.h"

namespace snort
{
struct SnortConfig;
}

#define ALPHABET_SIZE    256
#define ACSM_FAIL_STATE   (-1)

struct ACSM_USERDATA
{
    void* id;
    uint32_t ref_count;
};

struct ACSM_PATTERN
{
    ACSM_PATTERN* next;
    ACSM_USERDATA* udata;

    uint8_t* patrn;
    uint8_t* casepatrn;

    void* rule_option_tree;
    void* neg_list;

    int n;
    int nocase;
    int negative;
};

struct ACSM_STATETABLE
{
    /* Next state - based on input character */
    int NextState[ ALPHABET_SIZE ];

    /* Failure state - used while building NFA & DFA  */
    int FailState;

    /* List of patterns that end here, if any */
    ACSM_PATTERN* MatchList;
};

/*
* State machine Struct
*/
struct ACSM_STRUCT
{
    int acsmMaxStates;
    int acsmNumStates;

    ACSM_PATTERN* acsmPatterns;
    ACSM_STATETABLE* acsmStateTable;

    int bcSize;
    short bcShift[256];

    int numPatterns;
    const MpseAgent* agent;
};

/*
*   Prototypes
*/
void acsmx_init_xlatcase();

ACSM_STRUCT* acsmNew(const MpseAgent*);

int acsmAddPattern(ACSM_STRUCT* p, const uint8_t* pat, unsigned n,
    bool nocase, bool negative, void* id);

int acsmCompile(snort::SnortConfig*, ACSM_STRUCT*);

int acsmSearch(ACSM_STRUCT * acsm, const uint8_t* T,
    int n, MpseMatch, void* context, int* current_state);

void acsmFree(ACSM_STRUCT* acsm);
int acsmPatternCount(ACSM_STRUCT* acsm);

int acsmPrintDetailInfo(ACSM_STRUCT*);

int acsmPrintSummaryInfo();

#endif

