//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
// Copyright (C) 2001 Marc Norton
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

// sfksearch.h author Sourcefire Inc.

#ifndef KTRIE_H
#define KTRIE_H

// Trie based multi-pattern matcher

#define ALPHABET_SIZE 256

#ifdef WIN32
#define inline __inline
#endif

#define KTRIEMETHOD_STD 0
#define KTRIEMETHOD_QUEUE 1

struct KTRIEPATTERN
{
    KTRIEPATTERN* next; /* global list of all patterns */
    KTRIEPATTERN* mnext; /* matching list of duplicate keywords */

    unsigned char* P;   /* no case */
    unsigned char* Pcase; /* case sensitive */
    int n;
    int nocase;
    int negative;
    void* id;
    void* rule_option_tree;
    void* neg_list;
};

struct KTRIENODE
{
    int edge;   /* character */

    KTRIENODE* sibling;
    KTRIENODE* child;

    KTRIEPATTERN* pkeyword;
};

#define KTRIE_ROOT_NODES     256

#define SFK_MAX_INQ 32
struct SFK_PMQ
{
    unsigned inq;
    unsigned inq_flush;
    KTRIEPATTERN* q[SFK_MAX_INQ];
};

struct KTRIE_STRUCT
{
    KTRIEPATTERN* patrn; /* List of patterns, built as they are added */

    KTRIENODE* root[KTRIE_ROOT_NODES];    /* KTrie nodes */

    int memory;
    int nchars;
    int npats;
    int duplicates;
    int method;
    int end_states;          /* should equal npats - duplicates */

    int bcSize;
    unsigned short bcShift[KTRIE_ROOT_NODES];
    void (* userfree)(void* p);
    void (* optiontreefree)(void** p);
    void (* neg_list_free)(void** p);
    SFK_PMQ q;
};

KTRIE_STRUCT* KTrieNew(int method, void (* userfree)(void* p),
    void (* optiontreefree)(void** p),
    void (* neg_list_free)(void** p));
int KTrieAddPattern(KTRIE_STRUCT* ts, unsigned char* P, int n,
    int nocase, int negative, void* id);
int KTrieCompile(KTRIE_STRUCT* ts,
    int (* build_tree)(void* id, void** existing_tree),
    int (* neg_list_func)(void* id, void** list));
int KTrieSearch(KTRIE_STRUCT* ts, const unsigned char* T,  int n,
    int (* match)(void* id, void* tree, int index, void* data, void* neg_list),
    void* data);
unsigned int KTrieMemUsed();
void KTrieInitMemUsed();
void KTrieDelete(KTRIE_STRUCT* k);
int KTriePatternCount(KTRIE_STRUCT* k);

void sfksearch_print_qinfo();

#endif

