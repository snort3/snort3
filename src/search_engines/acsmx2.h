//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

// acsmx2.h author Marc Norton

#ifndef ACSMX2_H
#define ACSMX2_H

// Version 2.0

#include <cstdint>

#include "search_common.h"

namespace snort
{
struct SnortConfig;
}

#define MAX_ALPHABET_SIZE 256

/*
   FAIL STATE for 1,2,or 4 bytes for state transitions
   Uncomment this define to use 32 bit state values
   #define AC32
*/

#define AC32

#ifdef AC32

typedef unsigned int acstate_t;
#define ACSM_FAIL_STATE2  0xffffffff

#else

typedef unsigned short acstate_t;
#define ACSM_FAIL_STATE2 0xffff

#endif

struct ACSM_PATTERN2
{
    ACSM_PATTERN2* next;

    uint8_t* patrn;
    uint8_t* casepatrn;

    void* udata;
    void* rule_option_tree;
    void* neg_list;

    int n;
    int nocase;
    int negative;
};

/*
*    transition nodes  - either 8 or 12 bytes
*/
struct trans_node_t
{
    /* The character that got us here - sized to keep structure aligned on 4 bytes
     * to better the caching opportunities. A value that crosses the cache line
     * forces an expensive reconstruction, typing this as acstate_t stops that.
     */
    acstate_t key;
    acstate_t next_state;
    trans_node_t* next; /* next transition for this state */
};

/*
*  User specified final storage type for the state transitions
*/
enum
{
    ACF_FULL,
    ACF_SPARSE,
    ACF_BANDED,
    ACF_SPARSE_BANDS,
};

/*
*   Aho-Corasick State Machine Struct - one per group of patterns
*/
struct ACSM_STRUCT2
{
    ACSM_PATTERN2* acsmPatterns;
    acstate_t* acsmFailState;
    ACSM_PATTERN2** acsmMatchList;

    /* list of transitions in each state, this is used to build the nfa & dfa
       after construction we convert to sparse or full format matrix and free
       the transition lists */
    trans_node_t** acsmTransTable;
    acstate_t** acsmNextState;
    const MpseAgent* agent;

    int acsmMaxStates;
    int acsmNumStates;

    int acsmFormat;
    int acsmSparseMaxRowNodes;
    int acsmSparseMaxZcnt;

    int acsmNumTrans;
    int acsmAlphabetSize;
    int numPatterns;

    int sizeofstate;
    int compress_states;

    bool dfa;

    void enable_dfa()
    { dfa = true; }

    bool dfa_enabled()
    { return dfa; }
};

/*
*   Prototypes
*/
void acsmx2_init_xlatcase();

ACSM_STRUCT2* acsmNew2(const MpseAgent*, int format);

int acsmAddPattern2(
    ACSM_STRUCT2* p, const uint8_t* pat, unsigned n,
    bool nocase, bool negative, void* id);

int acsmCompile2(snort::SnortConfig*, ACSM_STRUCT2*);

int acsm_search_nfa(
    ACSM_STRUCT2*, const uint8_t* T, int n, MpseMatch, void* context, int* current_state);

int acsm_search_dfa_sparse(
    ACSM_STRUCT2*, const uint8_t* T, int n, MpseMatch, void* context, int* current_state);

int acsm_search_dfa_banded(
    ACSM_STRUCT2*, const uint8_t* T, int n, MpseMatch, void* context, int* current_state);

int acsm_search_dfa_full(
    ACSM_STRUCT2*, const uint8_t* T, int n, MpseMatch, void* context, int* current_state);

int acsm_search_dfa_full_all(
    ACSM_STRUCT2*, const uint8_t* Tx, int n, MpseMatch, void* context, int* current_state);

void acsmFree2(ACSM_STRUCT2*);
int acsmPatternCount2(ACSM_STRUCT2*);
void acsmCompressStates(ACSM_STRUCT2*, int);

void acsmPrintInfo2(ACSM_STRUCT2* p);

int acsmPrintDetailInfo2(ACSM_STRUCT2*);
int acsmPrintSummaryInfo2();
void acsmx2_print_qinfo();
void acsm_init_summary();

#endif

