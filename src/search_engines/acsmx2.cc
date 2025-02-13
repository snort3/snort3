//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 2003-2004 Daniel Roelker
// Copyright (C) 2002-2004 Marc Norton
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
**   All but the full storage format have been deleted. The full format
**   provides the best performance. Only the sparse bands format used
**   less memory than full and it was way slower. The ac_bnfa algorithm
**   is available for lower memory usage. The following notes are retained
**   to help make sense of the code.
**
**   acsmx2.c
**
**   Multi-Pattern Search Engine
**
**   Aho-Corasick State Machine - version 2.0
**
**   Supports both Non-Deterministic and Deterministic Finite Automata
**
**
**   Reference - Efficient String matching: An Aid to Bibliographic Search
**               Alfred V Aho and Margaret J Corasick
**               Bell Laboratories
**               Copyright (C) 1975 Association for Computing Machinery,Inc
**
**   +++
**   +++ Version 1.0 notes - Marc Norton:
**   +++
**
**   Original implementation based on the 4 algorithms in the paper by
**   Aho & Corasick, some implementation ideas from 'Practical Algorithms
**   in C', and some of my own.
**
**   1) Finds all occurrences of all patterns within a text.
**
**   +++
**   +++ Version 2.0 Notes - Marc Norton/Dan Roelker:
**   +++
**
**   New implementation modifies the state table storage and access model to
**   use compacted sparse vector storage. Dan Roelker and I hammered this
**   strategy out amongst many others in order to reduce memory usage and
**   improve caching performance.  The memory usage is greatly reduced, we
**   only use 1/4 of what we use to. The caching performance is better in
**   pure benchmarking tests, but does not show overall improvement in Snort.
**   Unfortunately, once a pattern match test has been performed Snort moves
**   on to doing many other things before we get back to a pattern match test,
**   so the cache is voided.
**
**   This versions has better caching performance characteristics, reduced
**   memory, more state table storage options, and requires no a priori case
**   conversions.  It does maintain the same public interface. (Snort only
**   used banded storage).
**
**     1) Supports NFA and DFA state machines, and basic keyword state machines
**     2) Initial transition table uses Linked Lists
**     3) Improved state table memory options. NFA and DFA state transition
**        tables are converted to one of 4 formats during compilation.
**        a) Full matrix
**        b) Sparse matrix
**        c) Banded matrix (Default-this is the only one used in snort)
**        d) Sparse-Banded matrix
**     4) Added support for acstate_t in .h file so we can compile states as
**        16, or 32 bit state values for another reduction in memory
**        consumption, smaller states allows more of the state table to be
**        cached, and improves performance on x86-P4.  Your mileage may vary,
**        especially on risc systems.
**     5) Added a bool to each state transition list to indicate if there is
**        a matching pattern in the state. This prevents us from accessing
**        another data array and can improve caching/performance.
**     6) The search functions are very sensitive, don't change them without
**        extensive testing, or you'll just spoil the caching and prefetching
**        opportunities.
**
**   Extras for fellow pattern matchers:
**    The table below explains the storage format used at each step.
**    You can use an NFA or DFA to match with, the NFA is slower but tiny -
**    set the structure directly.
**    You can use any of the 4 storage modes above -full, sparse, banded,
**    sparse-bands, set the structure directly.
**    For applications where you have lots of data and a pattern set to
**    search, this version was up to 3x faster than the previous version, due
**    to caching performance. This cannot be fully realized in Snort yet,
**    but other applications may have better caching opportunities.
**    Snort only needs to use the banded or full storage.
**
**  Transition table format at each processing stage.
**  -------------------------------------------------
**  Patterns -> Keyword State Table (List)
**  Keyword State Table -> NFA (List)
**  NFA -> DFA (List)
**  DFA (List)-> Sparse Rows  O(m-avg # transitions per state)
**        -> Banded Rows  O(1)
**            -> Sparse-Banded Rows O(nb-# bands)
**        -> Full Matrix  O(1)
**
** Notes:
**
** 8/28/06
** man - Sparse and SparseBands - fixed off by one in calculating matching index
**       SparseBands changed ps increment to 2+n to increment between bands.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "acsmx2.h"

#include <cassert>
#include <list>
#include <mutex>

#include "log/log_stats.h"
#include "log/messages.h"
#include "utils/util.h"

using namespace snort;

#define printf LogMessage

static int acsm2_total_memory = 0;
static int acsm2_pattern_memory = 0;
static int acsm2_matchlist_memory = 0;
static int acsm2_transtable_memory = 0;
static int acsm2_dfa_memory = 0;
static int acsm2_dfa1_memory = 0;
static int acsm2_dfa2_memory = 0;
static int acsm2_dfa4_memory = 0;
static int acsm2_failstate_memory = 0;

struct acsm_summary_t
{
    unsigned num_states;
    unsigned num_transitions;
    unsigned num_instances;
    unsigned num_patterns;
    unsigned num_characters;
    unsigned num_match_states;
    unsigned num_1byte_instances;
    unsigned num_2byte_instances;
    unsigned num_4byte_instances;
    ACSM_STRUCT2 acsm;
};

static acsm_summary_t summary;

void acsm_init_summary()
{
    summary.num_states = 0;
    summary.num_transitions = 0;
    summary.num_instances = 0;
    summary.num_patterns = 0;
    summary.num_characters = 0;
    summary.num_match_states = 0;
    summary.num_1byte_instances = 0;
    summary.num_2byte_instances = 0;
    summary.num_4byte_instances = 0;
    memset(&summary.acsm, 0, sizeof(ACSM_STRUCT2));
    acsm2_total_memory = 0;
    acsm2_pattern_memory = 0;
    acsm2_matchlist_memory = 0;
    acsm2_transtable_memory = 0;
    acsm2_dfa_memory = 0;
    acsm2_failstate_memory = 0;
}

static uint8_t xlatcase[256];
static bool xlatinit = true;

void acsmx2_init_xlatcase()
{
    static std::mutex _m;
    std::lock_guard<std::mutex> lock(_m);
    if ( !xlatinit )
       return;

    int i;
    for (i = 0; i < 256; i++)
    {
        xlatcase[i] = (uint8_t)toupper(i);
    }

    xlatinit = false;
}

static inline void ConvertCaseEx(uint8_t* d, const uint8_t* s, int m)
{
    for (int i=0; i < m; i++)
    {
        d[i] = xlatcase[ s[i] ];
    }
}

enum Acsm2MemoryType
{
    ACSM2_MEMORY_TYPE__NONE = 0,
    ACSM2_MEMORY_TYPE__PATTERN,
    ACSM2_MEMORY_TYPE__MATCHLIST,
    ACSM2_MEMORY_TYPE__TRANSTABLE,
    ACSM2_MEMORY_TYPE__FAILSTATE
};

static void* AC_MALLOC(int n, Acsm2MemoryType type)
{
    void* p = snort_calloc(n);

    switch (type)
    {
    case ACSM2_MEMORY_TYPE__PATTERN:
        acsm2_pattern_memory += n;
        break;
    case ACSM2_MEMORY_TYPE__MATCHLIST:
        acsm2_matchlist_memory += n;
        break;
    case ACSM2_MEMORY_TYPE__TRANSTABLE:
        acsm2_transtable_memory += n;
        break;
    case ACSM2_MEMORY_TYPE__FAILSTATE:
        acsm2_failstate_memory += n;
        break;
    case ACSM2_MEMORY_TYPE__NONE:
        break;
    default:
        assert(false);
    }
    acsm2_total_memory += n;

    return p;
}

static void* AC_MALLOC_DFA(int n, int sizeofstate)
{
    void* p = snort_calloc(n);

    switch (sizeofstate)
    {
    case 1:
        acsm2_dfa1_memory += n;
        break;
    case 2:
        acsm2_dfa2_memory += n;
        break;
    case 4:
    default:
        acsm2_dfa4_memory += n;
        break;
    }

    acsm2_dfa_memory += n;
    acsm2_total_memory += n;

    return p;
}

static void AC_FREE(void* p, int n, Acsm2MemoryType type)
{
    if (p != nullptr)
    {
        switch (type)
        {
        case ACSM2_MEMORY_TYPE__PATTERN:
            acsm2_pattern_memory -= n;
            break;
        case ACSM2_MEMORY_TYPE__MATCHLIST:
            acsm2_matchlist_memory -= n;
            break;
        case ACSM2_MEMORY_TYPE__TRANSTABLE:
            acsm2_transtable_memory -= n;
            break;
        case ACSM2_MEMORY_TYPE__FAILSTATE:
            acsm2_failstate_memory -= n;
            break;
        case ACSM2_MEMORY_TYPE__NONE:
        default:
            break;
        }

        acsm2_total_memory -= n;
        snort_free(p);
    }
}

static void AC_FREE_DFA(void* p, int n, int sizeofstate)
{
    if (p != nullptr)
    {
        switch (sizeofstate)
        {
        case 1:
            acsm2_dfa1_memory -= n;
            break;
        case 2:
            acsm2_dfa2_memory -= n;
            break;
        case 4:
        default:
            acsm2_dfa4_memory -= n;
            break;
        }

        acsm2_dfa_memory -= n;
        acsm2_total_memory -= n;
        snort_free(p);
    }
}


// Get Next State-NFA, using direct index to speed up search

static int List_GetNextStateOpt( ACSM_STRUCT2 * acsm,
    trans_node_t **acsmTransTableOpt, int state, int input )
{
    int index = state * acsm->acsmAlphabetSize + input;
    trans_node_t * t = acsmTransTableOpt[index];

    if ( t )
        return t->next_state;

    if( state == 0 )
        return 0;

    return ACSM_FAIL_STATE2; /* Fail state ??? */
}

// Get Next State-NFA

static int List_GetNextState(ACSM_STRUCT2* acsm, int state, int input)
{
    trans_node_t* t = acsm->acsmTransTable[state];

    while ( t )
    {
        if ( t->key == (acstate_t)input )
        {
            return t->next_state;
        }
        t=t->next;
    }

    if ( state == 0 )
        return 0;

    return ACSM_FAIL_STATE2; /* Fail state ??? */
}

// Get Next State-DFA

static int List_GetNextState2(ACSM_STRUCT2* acsm, int state, int input)
{
    trans_node_t* t = acsm->acsmTransTable[state];

    while ( t )
    {
        if ( t->key == (acstate_t)input )
        {
            return t->next_state;
        }
        t = t->next;
    }

    return 0; /* default state */
}

// Put Next State - Head insertion, and transition updates

static int List_PutNextStateOpt( ACSM_STRUCT2 * acsm, trans_node_t **acsmTransTableOpt,
        int state, int input, int next_state )
{
    int index = state * acsm->acsmAlphabetSize + input;

    trans_node_t *t = acsmTransTableOpt[index];

    if ( t )
    {
        t->next_state = next_state;
        return 0;
    }

    /* Definitely not an existing transition - add it */
    trans_node_t * tnew = (trans_node_t*)AC_MALLOC(sizeof(trans_node_t),
            ACSM2_MEMORY_TYPE__TRANSTABLE);

    if( !tnew )
        return -1;

    tnew->key        = input;
    tnew->next_state = next_state;
    tnew->next       = acsm->acsmTransTable[state];
    acsm->acsmTransTable[state] = tnew;
    acsm->acsmNumTrans++;

    acsmTransTableOpt[index] = tnew;

    return 0;
}

// Put Next State - Head insertion, and transition updates

static int List_PutNextState(ACSM_STRUCT2* acsm, int state, int input, int next_state)
{
    trans_node_t* p;
    trans_node_t* tnew;

    /* Check if the transition already exists, if so just update the next_state */
    p = acsm->acsmTransTable[state];
    while ( p )
    {
        /* transition already exists- reset the next state */
        if ( p->key == (acstate_t)input )
        {
            p->next_state = next_state;
            return 0;
        }
        p=p->next;
    }

    /* Definitely not an existing transition - add it */
    tnew = (trans_node_t*)AC_MALLOC(sizeof(trans_node_t), ACSM2_MEMORY_TYPE__TRANSTABLE);
    if ( !tnew )
        return -1;

    tnew->key        = input;
    tnew->next_state = next_state;
    tnew->next = acsm->acsmTransTable[state];

    acsm->acsmTransTable[state] = tnew;

    acsm->acsmNumTrans++;

    return 0;
}

//  Free the entire transition table

static int List_FreeTransTable(ACSM_STRUCT2* acsm)
{
    int i;
    trans_node_t* t, * p;

    if (acsm->acsmTransTable == nullptr)
        return 0;

    for (i = 0; i < acsm->acsmMaxStates; i++)
    {
        t = acsm->acsmTransTable[i];

        while (t != nullptr)
        {
            p = t->next;
            AC_FREE(t, sizeof(trans_node_t), ACSM2_MEMORY_TYPE__TRANSTABLE);
            t = p;
        }
    }

    AC_FREE(acsm->acsmTransTable, sizeof(void*) * acsm->acsmMaxStates,
        ACSM2_MEMORY_TYPE__TRANSTABLE);

    acsm->acsmTransTable = nullptr;

    return 0;
}


// Converts row of states from list to a full vector format

static inline int List_ConvToFull(ACSM_STRUCT2* acsm, acstate_t state, acstate_t* full)
{
    int tcnt = 0;
    trans_node_t* t = acsm->acsmTransTable[state];

    if (t == nullptr)
        return 0;

    while (t != nullptr)
    {
        switch (acsm->sizeofstate)
        {
        case 1:
            *((uint8_t*)full + t->key) = (uint8_t)t->next_state;
            break;
        case 2:
            *((uint16_t*)full + t->key) = (uint16_t)t->next_state;
            break;
        default:
            full[t->key] = t->next_state;
            break;
        }

        tcnt++;
        t = t->next;
    }

    return tcnt;
}


// Copy a Match List Entry - don't dup the pattern data

static ACSM_PATTERN2* CopyMatchListEntry(ACSM_PATTERN2* px)
{
    ACSM_PATTERN2* p;

    p = (ACSM_PATTERN2*)AC_MALLOC(sizeof (ACSM_PATTERN2), ACSM2_MEMORY_TYPE__MATCHLIST);

    memcpy(p, px, sizeof (ACSM_PATTERN2));

    return p;
}

// Add a pattern to the list of patterns terminated at this state.
// Insert at front of list.

static void AddMatchListEntry(ACSM_STRUCT2* acsm, int state, ACSM_PATTERN2* px)
{
    ACSM_PATTERN2* p;

    p = (ACSM_PATTERN2*)AC_MALLOC(sizeof (ACSM_PATTERN2), ACSM2_MEMORY_TYPE__MATCHLIST);

    memcpy(p, px, sizeof (ACSM_PATTERN2));
    p->next = acsm->acsmMatchList[state];

    acsm->acsmMatchList[state] = p;
}

static void AddPatternStates(ACSM_STRUCT2* acsm, ACSM_PATTERN2* p)
{
    int state = 0;
    int n = p->n;
    uint8_t* pattern = p->patrn;

    // Match up pattern with existing states

    for (; n > 0; pattern++, n--)
    {
        int next = List_GetNextState(acsm,state,*pattern);

        if ((acstate_t)next == ACSM_FAIL_STATE2 || next == 0)
            break;

        state = next;
    }

    // Add new states for the rest of the pattern bytes, 1 state per byte

    for (; n > 0; pattern++, n--)
    {
        acsm->acsmNumStates++;
        List_PutNextState(acsm,state,*pattern,acsm->acsmNumStates);
        state = acsm->acsmNumStates;
    }

    AddMatchListEntry (acsm, state, p);
}

// Build A Non-Deterministic Finite Automata
// The keyword state table must already be built, via AddPatternStates().

static void Build_NFA(ACSM_STRUCT2* acsm)
{
    acstate_t* FailState = acsm->acsmFailState;
    ACSM_PATTERN2** MatchList = acsm->acsmMatchList;
    ACSM_PATTERN2* mlist, * px;

    std::list<int> queue;

    bool* queue_array = (bool*) snort_calloc( acsm->acsmNumStates, sizeof(bool) );

    /* Add the state 0 transitions 1st, the states at depth 1, fail to state 0 */
    for (int i = 0; i < acsm->acsmAlphabetSize; i++)
    {
        int s = List_GetNextState2(acsm,0,i);

        if ( s )
        {
            if ( !queue_array[s] )
            {
                queue.emplace_back(s);
                queue_array[s] = true;
            }
            FailState[s] = 0;
        }
    }

    /* Build the fail state successive layer of transitions */
    for ( auto r : queue )
    {
        queue_array[r] = false;

        /* Find Final States for any Failure */
        for (int i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            int s = List_GetNextState(acsm,r,i);

            if ( (acstate_t)s != ACSM_FAIL_STATE2 )
            {
                if ( !queue_array[s] )
                {
                    queue.emplace_back(s);
                    queue_array[s] = true;
                }
                int fs = FailState[r];
                int next;

                /*
                 *  Locate the next valid state for 'i' starting at fs
                 */
                while ((acstate_t)(next = List_GetNextState(acsm,fs,i)) == ACSM_FAIL_STATE2 )
                {
                    fs = FailState[fs];
                }

                /*
                 *  Update 's' state failure state to point to the next valid state
                 */
                FailState[s] = next;

                /*
                 *  Copy 'next' states MatchList to 's' states MatchList,
                 *  we copy them so each list can be AC_FREE'd later,
                 *  else we could just manipulate pointers to fake the copy.
                 */
                for ( mlist = MatchList[next];
                    mlist;
                    mlist = mlist->next)
                {
                    px = CopyMatchListEntry (mlist);

                    /* Insert at front of MatchList */
                    px->next = MatchList[s];
                    MatchList[s] = px;
                }
            }
        }
    }

    snort_free(queue_array);
}

// Build Deterministic Finite Automata from the NFA

static void Convert_NFA_To_DFA(ACSM_STRUCT2* acsm)
{
    int cFailState;
    acstate_t* FailState = acsm->acsmFailState;

    std::list<int> queue;
    bool* queue_array = (bool*) snort_calloc( acsm->acsmNumStates, sizeof(bool) );
    trans_node_t** acsmTransTableOpt = (trans_node_t**)
        snort_calloc( acsm->acsmAlphabetSize * acsm->acsmNumStates, sizeof(trans_node_t*) );

    for ( int i = 0; i < acsm->acsmNumStates; i++ )
    {
        trans_node_t* t = acsm->acsmTransTable[i];
        while ( t )
        {
            int index = i * acsm->acsmAlphabetSize + t->key;
            acsmTransTableOpt[index] = t;
            t = t->next;
        }
    }

    /* Add the state 0 transitions 1st */
    for (int i=0; i<acsm->acsmAlphabetSize; i++)
    {
        if ( int s = List_GetNextStateOpt(acsm, acsmTransTableOpt, 0, i) )
        {
            if ( !queue_array[s] )
            {
                queue.emplace_back(s);
                queue_array[s] = true;
            }
        }
    }

    /* Start building the next layer of transitions */
    for ( auto r : queue )
    {
        queue_array[r] = false;

        /* Process this states layer */
        for (int i = 0; i < acsm->acsmAlphabetSize; i++)
        {
            int s = List_GetNextStateOpt(acsm, acsmTransTableOpt, r, i);

            if ( (acstate_t)s != ACSM_FAIL_STATE2 && s != 0 )
            {
                if ( !queue_array[s] )
                {
                    queue.emplace_back(s);
                    queue_array[s] = true;
                }
            }
            else
            {
                cFailState = List_GetNextStateOpt(acsm, acsmTransTableOpt, FailState[r], i);

                if ( cFailState != 0 && (acstate_t)cFailState != ACSM_FAIL_STATE2 )
                {
                    List_PutNextStateOpt(acsm, acsmTransTableOpt, r, i, cFailState);
                }
            }
        }
    }

    snort_free(queue_array);
    snort_free(acsmTransTableOpt);
}

// Convert a row lists for the state table to a full vector format

static int Conv_List_To_Full(ACSM_STRUCT2* acsm)
{
    acstate_t k;
    acstate_t* p;
    acstate_t** NextState = acsm->acsmNextState;

    for (k = 0; k < (acstate_t)acsm->acsmNumStates; k++)
    {
        p = (acstate_t*)AC_MALLOC_DFA(acsm->sizeofstate * (acsm->acsmAlphabetSize + 2),
            acsm->sizeofstate);
        if (p == nullptr)
            return -1;

        switch (acsm->sizeofstate)
        {
        case 1:
            List_ConvToFull(acsm, k, (acstate_t*)((uint8_t*)p + 2));
            *((uint8_t*)p) = 0;
            *((uint8_t*)p + 1) = 0;
            break;
        case 2:
            List_ConvToFull(acsm, k, (acstate_t*)((uint16_t*)p + 2));
            *((uint16_t*)p) = 0;
            *((uint16_t*)p + 1) = 0;
            break;
        default:
            List_ConvToFull(acsm, k, (p + 2));
            p[0] = 0;
            p[1] = 0; /* no matches yet */
            break;
        }

        NextState[k] = p; /* now we have a full format row vector  */
    }

    return 0;
}

// Create a new AC full state machine

ACSM_STRUCT2* acsmNew2(const MpseAgent* agent)
{
    ACSM_STRUCT2* p = (ACSM_STRUCT2*)AC_MALLOC(sizeof (ACSM_STRUCT2), ACSM2_MEMORY_TYPE__NONE);

    p->agent = agent;
    p->acsmAlphabetSize = 256;

    return p;
}

// Add a pattern to the list of patterns for this state machine

int acsmAddPattern2(
    ACSM_STRUCT2* p, const uint8_t* pat, unsigned n, bool nocase,
    bool negative, void* user)
{
    ACSM_PATTERN2* plist;

    plist = (ACSM_PATTERN2*)
        AC_MALLOC(sizeof (ACSM_PATTERN2), ACSM2_MEMORY_TYPE__PATTERN);

    plist->patrn =
        (uint8_t*)AC_MALLOC(n, ACSM2_MEMORY_TYPE__PATTERN);

    ConvertCaseEx(plist->patrn, pat, n);

    plist->casepatrn =
        (uint8_t*)AC_MALLOC(n, ACSM2_MEMORY_TYPE__PATTERN);

    memcpy(plist->casepatrn, pat, n);

    plist->n = n;
    plist->nocase = nocase;
    plist->negative = negative;
    plist->udata = user;

    plist->next = p->acsmPatterns;
    p->acsmPatterns = plist;
    p->numPatterns++;

    return 0;
}

// Copy a boolean match flag int NextState table, for caching purposes.

static void acsmUpdateMatchStates(ACSM_STRUCT2* acsm)
{
    acstate_t state;
    acstate_t** NextState = acsm->acsmNextState;
    ACSM_PATTERN2** MatchList = acsm->acsmMatchList;

    for (state = 0; state < (acstate_t)acsm->acsmNumStates; state++)
    {
        acstate_t* p = NextState[state];

        if (MatchList[state])
        {
            switch (acsm->sizeofstate)
            {
            case 1:
                *((uint8_t*)p + 1) = 1;
                break;
            case 2:
                *((uint16_t*)p + 1) = 1;
                break;
            default:
                p[1] = 1;
                break;
            }

            summary.num_match_states++;
        }
    }
}

static void acsmBuildMatchStateTrees2(SnortConfig* sc, ACSM_STRUCT2* acsm)
{
    ACSM_PATTERN2** MatchList = acsm->acsmMatchList;
    ACSM_PATTERN2* mlist;

    /* Find the states that have a MatchList */
    for (int i = 0; i < acsm->acsmNumStates; i++)
    {
        for ( mlist=MatchList[i]; mlist!=nullptr; mlist=mlist->next )
        {
            if (mlist->udata)
            {
                if (mlist->negative)
                {
                    acsm->agent->negate_list(mlist->udata, &MatchList[i]->neg_list);
                }
                else
                {
                    acsm->agent->build_tree(sc, mlist->udata, &MatchList[i]->rule_option_tree);
                }
            }
        }

        if (MatchList[i])
        {
            /* Last call to finalize the tree */
            acsm->agent->build_tree(sc, nullptr, &MatchList[i]->rule_option_tree);
        }
    }
}

//  Compile State Machine - NFA or DFA and Full

static inline int _acsmCompile2(ACSM_STRUCT2* acsm)
{
    ACSM_PATTERN2* plist;

    /* Count number of possible states */
    for (plist = acsm->acsmPatterns; plist != nullptr; plist = plist->next)
        acsm->acsmMaxStates += plist->n;

    acsm->acsmMaxStates++; /* one extra */

    /* Alloc a List based State Transition table */
    acsm->acsmTransTable =
        (trans_node_t**)AC_MALLOC(sizeof(trans_node_t*) * acsm->acsmMaxStates,
            ACSM2_MEMORY_TYPE__TRANSTABLE);

    /* Alloc a MatchList table - this has a list of pattern matches for each state, if any */
    acsm->acsmMatchList =
        (ACSM_PATTERN2**)AC_MALLOC(sizeof(ACSM_PATTERN2*) * acsm->acsmMaxStates,
            ACSM2_MEMORY_TYPE__MATCHLIST);

    /* Initialize state zero as a branch */
    acsm->acsmNumStates = 0;

    /* Add each Pattern to the State Table - This forms a keywords state table  */
    for (plist = acsm->acsmPatterns; plist != nullptr; plist = plist->next)
    {
        summary.num_patterns++;
        summary.num_characters += plist->n;
        AddPatternStates(acsm, plist);
    }

    /* Add the 0'th state */
    acsm->acsmNumStates++;

    if (acsm->acsmNumStates < UINT8_MAX)
    {
        acsm->sizeofstate = 1;
        summary.num_1byte_instances++;
    }
    else if (acsm->acsmNumStates < UINT16_MAX)
    {
        acsm->sizeofstate = 2;
        summary.num_2byte_instances++;
    }
    else
    {
        acsm->sizeofstate = 4;
        summary.num_4byte_instances++;
    }

    /* Alloc a failure table - this has a failure state, and a match list for each state */
    acsm->acsmFailState =
        (acstate_t*)AC_MALLOC(sizeof(acstate_t) * acsm->acsmNumStates,
            ACSM2_MEMORY_TYPE__FAILSTATE);

    /* Alloc a separate state transition table == in state 's' due to event 'k', transition to
      'next' state */
    acsm->acsmNextState =
        (acstate_t**)AC_MALLOC_DFA(acsm->acsmNumStates * sizeof(acstate_t*), acsm->sizeofstate);

    Build_NFA(acsm);
    Convert_NFA_To_DFA(acsm);

    /* Don't need the FailState table anymore */
    AC_FREE(acsm->acsmFailState, sizeof(acstate_t) * acsm->acsmNumStates, ACSM2_MEMORY_TYPE__FAILSTATE);
    acsm->acsmFailState = nullptr;

    if ( Conv_List_To_Full(acsm) )
        return -1;

    /* load boolean match flags into state table */
    acsmUpdateMatchStates(acsm);

    /* Free up the Table Of Transition Lists */
    List_FreeTransTable(acsm);

    /* Accrue Summary State Stats */
    summary.num_states += acsm->acsmNumStates;
    summary.num_transitions += acsm->acsmNumTrans;
    summary.num_instances++;

    memcpy(&summary.acsm, acsm, sizeof(ACSM_STRUCT2));

    return 0;
}

int acsmCompile2(SnortConfig* sc, ACSM_STRUCT2* acsm)
{
    if ( int rval = _acsmCompile2(acsm) )
        return rval;

    if ( acsm->agent )
        acsmBuildMatchStateTrees2(sc, acsm);

    return 0;
}

/*
*   Full format DFA search
*   Do not change anything here without testing, caching and prefetching
*   performance is very sensitive to any changes.
*
*   Perf-Notes:
*    1) replaced ConvertCaseEx with inline xlatcase - this improves performance 5-10%
*    2) using 'nocase' improves performance again by 10-15%, since memcmp is not needed
*    3)
*/
#define AC_SEARCH \
    for (; T < Tend; T++ ) \
    { \
        ps = NextState[ state ]; \
        sindex = xlatcase[T[0]]; \
        if (ps[1]) \
        { \
            mlist = MatchList[state]; \
            if (mlist) \
            { \
                index = T - Tx; \
                nfound++; \
                if (match (mlist->udata, mlist->rule_option_tree, index, context, \
                    mlist->neg_list) > 0) \
                { \
                    *current_state = state; \
                    return nfound; \
                } \
            } \
        } \
        state = ps[2u + sindex]; \
    }

int acsm_search_dfa_full(
    ACSM_STRUCT2* acsm, const uint8_t* Tx, int n, MpseMatch match,
    void* context, int* current_state
    )
{
    ACSM_PATTERN2* mlist;
    const uint8_t* Tend;
    const uint8_t* T;
    int index;
    int sindex;
    int nfound = 0;
    acstate_t state;
    ACSM_PATTERN2** MatchList = acsm->acsmMatchList;

    T = Tx;
    Tend = Tx + n;

    if (current_state == nullptr)
        return 0;

    state = *current_state;

    switch (acsm->sizeofstate)
    {
    case 1:
    {
        uint8_t* ps;
        uint8_t** NextState = (uint8_t**)acsm->acsmNextState;
        AC_SEARCH
    }
    break;
    case 2:
    {
        uint16_t* ps;
        uint16_t** NextState = (uint16_t**)acsm->acsmNextState;
        AC_SEARCH
    }
    break;
    default:
    {
        acstate_t* ps;
        acstate_t** NextState = acsm->acsmNextState;
        AC_SEARCH
    }
    break;
    }

    /* Check the last state for a pattern match */
    mlist = MatchList[state];
    if (mlist)
    {
        index = T - Tx;
        nfound++;
        if (match(mlist->udata, mlist->rule_option_tree, index, context, mlist->neg_list) > 0)
        {
            *current_state = state;
            return nfound;
        }
    }

    *current_state = state;
    return nfound;
}

/*
*   Full format DFA search
*   Do not change anything here without testing, caching and prefetching
*   performance is very sensitive to any changes.
*
*   Perf-Notes:
*    1) replaced ConvertCaseEx with inline xlatcase - this improves performance 5-10%
*    2) using 'nocase' improves performance again by 10-15%, since memcmp is not needed
*    3)
*/
#define AC_SEARCH_ALL \
    for (; T < Tend; T++ ) \
    { \
        ps = NextState[ state ]; \
        sindex = xlatcase[T[0]]; \
        if (ps[1]) \
        { \
            for ( mlist = MatchList[state]; \
                mlist!= nullptr; \
                mlist = mlist->next ) \
            { \
                index = T - Tx; \
                if ( mlist->nocase || (memcmp (mlist->casepatrn, T - mlist->n, mlist->n) == 0)) \
                { \
                    nfound++; \
                    if (match (mlist->udata, mlist->rule_option_tree, index, context, \
                        mlist->neg_list) > 0) \
                    { \
                        *current_state = state; \
                        return nfound; \
                    } \
                } \
            } \
        } \
        state = ps[2u + sindex]; \
    }

int acsm_search_dfa_full_all(
    ACSM_STRUCT2* acsm, const uint8_t* Tx, int n, MpseMatch match,
    void* context, int* current_state)
{
    ACSM_PATTERN2* mlist;
    const uint8_t* Tend;
    const uint8_t* T;
    int index;
    int sindex;
    int nfound = 0;
    acstate_t state;
    ACSM_PATTERN2** MatchList = acsm->acsmMatchList;

    T = Tx;
    Tend = Tx + n;

    if (current_state == nullptr)
        return 0;

    state = *current_state;

    switch (acsm->sizeofstate)
    {
    case 1:
    {
        uint8_t* ps;
        uint8_t** NextState = (uint8_t**)acsm->acsmNextState;
        AC_SEARCH_ALL
    }
    break;
    case 2:
    {
        uint16_t* ps;
        uint16_t** NextState = (uint16_t**)acsm->acsmNextState;
        AC_SEARCH_ALL
    }
    break;
    default:
    {
        acstate_t* ps;
        acstate_t** NextState = acsm->acsmNextState;
        AC_SEARCH_ALL
    }
    break;
    }

    /* Check the last state for a pattern match */
    for ( mlist = MatchList[state];
        mlist!= nullptr;
        mlist = mlist->next )
    {
        index = T - Tx;

        if ( mlist->nocase || (memcmp (mlist->casepatrn, T - mlist->n, mlist->n) == 0))
        {
            nfound++;
            if (match(mlist->udata, mlist->rule_option_tree, index, context, mlist->neg_list) > 0)
            {
                *current_state = state;
                return nfound;
            }
        }
    }

    *current_state = state;
    return nfound;
}

// Free all memory

void acsmFree2(ACSM_STRUCT2* acsm)
{
    int i;
    ACSM_PATTERN2* mlist, * ilist, * plist;

    /* For AC_FREE don't really care at this point about stats */

    for (i = 0; i < acsm->acsmNumStates; i++)
    {
        mlist = acsm->acsmMatchList[i];

        while (mlist)
        {
            ilist = mlist;
            mlist = mlist->next;

            if (ilist->rule_option_tree && acsm->agent)
                acsm->agent->tree_free(&(ilist->rule_option_tree));

            if (ilist->neg_list && acsm->agent)
                acsm->agent->list_free(&(ilist->neg_list));

            AC_FREE(ilist, 0, ACSM2_MEMORY_TYPE__NONE);
        }

        AC_FREE_DFA(acsm->acsmNextState[i], 0, 0);
    }

    for (plist = acsm->acsmPatterns; plist; )
    {
        ACSM_PATTERN2* tmpPlist = plist->next;

        if (acsm->agent && (plist->udata != nullptr))
            acsm->agent->user_free(plist->udata);

        AC_FREE(plist->patrn, 0, ACSM2_MEMORY_TYPE__NONE);
        AC_FREE(plist->casepatrn, 0, ACSM2_MEMORY_TYPE__NONE);
        AC_FREE(plist, 0, ACSM2_MEMORY_TYPE__NONE);

        plist = tmpPlist;
    }

    AC_FREE_DFA(acsm->acsmNextState, 0, 0);
    AC_FREE(acsm->acsmFailState, 0, ACSM2_MEMORY_TYPE__NONE);
    AC_FREE(acsm->acsmMatchList, 0, ACSM2_MEMORY_TYPE__NONE);
    AC_FREE(acsm, 0, ACSM2_MEMORY_TYPE__NONE);
}

int acsmPatternCount2(ACSM_STRUCT2* acsm)
{
    return acsm->numPatterns;
}

static void Print_DFA_MatchList(ACSM_STRUCT2* acsm, int state)
{
    ACSM_PATTERN2* mlist;

    for (mlist = acsm->acsmMatchList[state];
        mlist;
        mlist = mlist->next)
    {
        printf("%.*s ", mlist->n, mlist->patrn);
    }
}

static void Print_DFA(ACSM_STRUCT2* acsm)
{
    int k,i;
    acstate_t* p, state, fmt;
    acstate_t** NextState = acsm->acsmNextState;

    printf("Print DFA - %d active states\n",acsm->acsmNumStates);

    for (k=0; k<acsm->acsmNumStates; k++)
    {
        p   = NextState[k];

        if ( !p )
            continue;

        fmt = *p++;

        printf("state %3d, fmt=%d: ",k,fmt);

        for ( i=0; i<acsm->acsmAlphabetSize; i++ )
        {
            state = p[i];

            if ( state != 0 && state != ACSM_FAIL_STATE2 )
            {
                if ( isascii(i) && isprint(i) )
                    printf("%3c->%-5d\t",i,state);
                else
                    printf("%3d->%-5d\t",i,state);
            }
        }

        Print_DFA_MatchList(acsm, k);

        printf("\n");
    }
}

int acsmPrintDetailInfo2(ACSM_STRUCT2* acsm)
{
    Print_DFA(acsm);
    return 0;
}

/*
 *   Global summary of all info and all state machines built during this run
 *   This feeds off of the last pattern groupd built within snort,
 *   all groups use the same format, state size, etc..
 *   Combined with accrued stats, we get an average picture of things.
 */

int acsmPrintSummaryInfo2()
{
    ACSM_STRUCT2* p = &summary.acsm;

    if ( !summary.num_states )
        return 0;

    LogValue("storage format", "full");
    LogValue("finite automaton", "DFA");
    LogCount("alphabet size", p->acsmAlphabetSize);

    LogCount("instances", summary.num_instances);
    LogCount("patterns", summary.num_patterns);
    LogCount("pattern chars", summary.num_characters);

    LogCount("states", summary.num_states);
    LogCount("transitions", summary.num_transitions);
    LogCount("match states", summary.num_match_states);

    LogValue("sizeof state", "1, 2, or 4");

    if ( summary.num_1byte_instances )
        LogCount("1 byte states", summary.num_1byte_instances);

    if ( summary.num_2byte_instances )
        LogCount("2 byte states", summary.num_2byte_instances);

    if ( summary.num_4byte_instances )
        LogCount("4 byte states", summary.num_4byte_instances);

    double scale;

    if ( acsm2_total_memory < 1024*1024 )
    {
        scale = 1024;
        LogValue("memory scale", "KB");
    }
    else
    {
        scale = 1024 * 1024;
        LogValue("memory scale", "MB");
    }
    LogStat("total memory", acsm2_total_memory/scale);
    LogStat("pattern memory", acsm2_pattern_memory/scale);
    LogStat("match list memory", acsm2_matchlist_memory/scale);
    LogStat("transition memory", acsm2_transtable_memory/scale);
    LogStat("fail state memory", acsm2_failstate_memory/scale);

#if 0  // FIXIT-L clean up format; not all this should be printed all the time
    if (acsm2_dfa_memory > 0)
    {
        LogMessage("|   DFA\n");
        LogMessage("|     1 byte states : %.2f\n", acsm2_dfa1_memory/scale);
        LogMessage("|     2 byte states : %.2f\n", acsm2_dfa2_memory/scale);
        LogMessage("|     4 byte states : %.2f\n", acsm2_dfa4_memory/scale);
    }
#endif

    return 0;
}

