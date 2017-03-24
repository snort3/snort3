//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SFKSEARCH_H
#define SFKSEARCH_H

// ksearch.h - Trie based multi-pattern matcher

#include <stdint.h>
#include "search_engines/search_common.h"

struct KTRIEPATTERN
{
    KTRIEPATTERN* next; /* global list of all patterns*/
    KTRIEPATTERN* mnext; /* matching list of duplicate keywords*/

    uint8_t* P;  /* no case*/
    uint8_t* Pcase; /* case sensitive*/

    void* user;
    void* rule_option_tree;
    void* neg_list;

    int n;
    int nocase;
    int negative;
};

struct KTRIENODE
{
    int edge;   /* character*/

    KTRIENODE* sibling;
    KTRIENODE* child;

    KTRIEPATTERN* pkeyword;
};

#define KTRIE_ROOT_NODES     256

struct KTRIE_STRUCT
{
    KTRIEPATTERN* patrn; /* List of patterns, built as they are added*/
    KTRIENODE* root[KTRIE_ROOT_NODES];   /* KTrie nodes*/

    const struct MpseAgent* agent;

    int memory;
    int nchars;
    int npats;
    int duplicates;
    int method;
    int end_states;          /* should equal npats - duplicates*/

    int bcSize;
    unsigned short bcShift[KTRIE_ROOT_NODES];
};

void KTrie_init_xlatcase();

KTRIE_STRUCT* KTrieNew(int method, const MpseAgent*);

int KTrieAddPattern(
    KTRIE_STRUCT*, const uint8_t* P, unsigned n,
    bool nocase, bool negative, void* id);

int KTrieCompile(struct SnortConfig*, KTRIE_STRUCT*);

int KTrieSearch(KTRIE_STRUCT*, const uint8_t* T,  int n, MpseMatch, void* context);

unsigned int KTrieMemUsed();
void KTrieInitMemUsed();

void KTrieDelete(KTRIE_STRUCT*);
int KTriePatternCount(KTRIE_STRUCT*);

void sfksearch_print_qinfo();

#endif

