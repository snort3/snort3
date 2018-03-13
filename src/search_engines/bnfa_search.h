//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// bnfa_search.h author Marc Norton <mnorton@sourcefire.com>

#ifndef BNFA_SEARCH_H
#define BNFA_SEARCH_H

/*
** Basic NFA based multi-pattern search using Aho_corasick construction,
** and compacted sparse storage.
**
** Version 3.0
** date:   12/21/05
*/

#include <cstdint>

#include "search_common.h"

namespace snort
{
struct SnortConfig;
}

/* debugging - allow printing the trie and nfa in list format
   #define ALLOW_LIST_PRINT */

/* debugging - enable full format
   #define ALLOW_NFA_FULL */

/*
*   DEFINES and Typedef's
*/
//#define SPARSE_FULL_STATE_0
#define BNFA_MAX_ALPHABET_SIZE          256
#define BNFA_FAIL_STATE                 0xffffffff
#define BNFA_SPARSE_LINEAR_SEARCH_LIMIT 6

#define BNFA_SPARSE_MAX_STATE           0x00ffffff
#define BNFA_SPARSE_COUNT_SHIFT         24
#define BNFA_SPARSE_VALUE_SHIFT         24

#define BNFA_SPARSE_MATCH_BIT           0x80000000
#define BNFA_SPARSE_FULL_BIT            0x40000000
#define BNFA_SPARSE_COUNT_BITS          0x3f000000
#define BNFA_SPARSE_MAX_ROW_TRANSITIONS 0x3f

typedef  unsigned int bnfa_state_t;

/*
*   Internal Pattern Representation
*/
struct bnfa_pattern_t
{
    bnfa_pattern_t* next;
    uint8_t* casepatrn;   /* case specific */
    void* userdata;       /* ptr to users pattern data/info  */

    unsigned n;           /* pattern len */
    int nocase;           /* nocase flag */
    int negative;         /* pattern is negated */
};

/*
*  List format transition node
*/
struct bnfa_trans_node_t
{
    bnfa_trans_node_t* next;
    bnfa_state_t key;
    bnfa_state_t next_state;
};

/*
*  List format patterns
*/
struct bnfa_match_node_t
{
    void* data;
    void* rule_option_tree;
    void* neg_list;
    bnfa_match_node_t* next;
};

/*
*  Final storage type for the state transitions
*/
enum
{
    BNFA_FULL,
    BNFA_SPARSE
};

enum
{
    BNFA_PER_PAT_CASE,
    BNFA_CASE,
    BNFA_NOCASE
};

/*
*   Aho-Corasick State Machine Struct
*/
struct bnfa_struct_t
{
    int bnfaMethod;
    int bnfaCaseMode;
    int bnfaFormat;
    int bnfaAlphabetSize;
    int bnfaOpt;

    unsigned bnfaPatternCnt;

    int bnfaMaxStates;
    int bnfaNumStates;
    int bnfaNumTrans;
    int bnfaMatchStates;

    bnfa_pattern_t* bnfaPatterns;
    bnfa_trans_node_t** bnfaTransTable;
    bnfa_state_t** bnfaNextState;
    bnfa_match_node_t** bnfaMatchList;
    bnfa_state_t* bnfaFailState;
    bnfa_state_t* bnfaTransList;

    const MpseAgent* agent;

    int bnfaForceFullZeroState;

    int bnfa_memory;
    int pat_memory;
    int list_memory;
    int queue_memory;
    int nextstate_memory;
    int failstate_memory;
    int matchlist_memory;
};

/*
*   Prototypes
*/
void bnfa_init_xlatcase();

bnfa_struct_t* bnfaNew(const MpseAgent*);

void bnfaSetOpt(bnfa_struct_t* p, int flag);
void bnfaSetCase(bnfa_struct_t* p, int flag);
void bnfaFree(bnfa_struct_t* pstruct);

int bnfaAddPattern(
    bnfa_struct_t* pstruct, const uint8_t* pat, unsigned patlen,
    bool nocase, bool negative, void* userdata);

int bnfaCompile(snort::SnortConfig*, bnfa_struct_t*);

unsigned _bnfa_search_csparse_nfa(
    bnfa_struct_t * pstruct, const uint8_t* t, int tlen, MpseMatch,
    void* context, unsigned sindex, int* current_state);

int bnfaPatternCount(bnfa_struct_t* p);

void bnfaPrint(bnfa_struct_t* pstruct);   /* prints the nfa states-verbose!! */
void bnfaPrintInfo(bnfa_struct_t* pstruct);    /* print info on this search engine */

/*
 * Summary - this tracks search engine information across multiple instances of
 * search engines.  It helps in snort where we have many search engines, each using
 * rule grouping, to track total patterns, states, memory, etc...
 *
 */
void bnfaPrintInfoEx(bnfa_struct_t* p, const char* text);
void bnfaAccumInfo(bnfa_struct_t* pstruct);  // add info to summary over multiple search engines
void bnfaPrintSummary(); /* print current summary */
void bnfaInitSummary();  /* reset accumulator for global summary over multiple engines */
void bnfa_print_qinfo();
#endif

