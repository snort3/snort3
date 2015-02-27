//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

/*
**   ACSMX.H
**
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "search_common.h"

#ifndef ACSMX_H
#define ACSMX_H

/*
*   Prototypes
*/

#define ALPHABET_SIZE    256

#define ACSM_FAIL_STATE   -1

typedef struct _acsm_userdata
{
    uint32_t ref_count;
    void* id;
} ACSM_USERDATA;

typedef struct _acsm_pattern
{
    struct  _acsm_pattern* next;
    unsigned char* patrn;
    unsigned char* casepatrn;
    int n;
    int nocase;
    int negative;
    int iid;
    ACSM_USERDATA* udata;
    void* rule_option_tree;
    void* neg_list;
} ACSM_PATTERN;

typedef struct
{
    /* Next state - based on input character */
    int NextState[ ALPHABET_SIZE ];

    /* Failure state - used while building NFA & DFA  */
    int FailState;

    /* List of patterns that end here, if any */
    ACSM_PATTERN* MatchList;
}ACSM_STATETABLE;

/*
* State machine Struct
*/
typedef struct
{
    int acsmMaxStates;
    int acsmNumStates;

    ACSM_PATTERN* acsmPatterns;
    ACSM_STATETABLE* acsmStateTable;

    int bcSize;
    short bcShift[256];

    int numPatterns;
    void (* userfree)(void* p);
    void (* optiontreefree)(void** p);
    void (* neg_list_free)(void** p);
}ACSM_STRUCT;

/*
*   Prototypes
*/
void acsmx_init_xlatcase();

ACSM_STRUCT* acsmNew(void (* userfree)(void* p),
    void (* optiontreefree)(void** p),
    void (* neg_list_free)(void** p));

int acsmAddPattern(ACSM_STRUCT* p, const uint8_t* pat, unsigned n,
    bool nocase, bool negative, void* id, int iid);

int acsmCompile(ACSM_STRUCT* acsm,
    int (* build_tree)(void* id, void** existing_tree),
    int (* neg_list_func)(void* id, void** list));

struct SnortConfig;

int acsmCompile(
    SnortConfig*,
    ACSM_STRUCT* acsm,
    int (* build_tree)(SnortConfig*, void* id, void** existing_tree),
    int (* neg_list_func)(void* id, void** list));

int acsmSearch (
ACSM_STRUCT * acsm,unsigned char* T, int n, MpseCallback,
void* data, int* current_state);

void acsmFree(ACSM_STRUCT* acsm);
int acsmPatternCount(ACSM_STRUCT* acsm);

int acsmPrintDetailInfo(ACSM_STRUCT*);

int acsmPrintSummaryInfo(void);

#endif

