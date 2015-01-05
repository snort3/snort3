/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2003-2013 Sourcefire, Inc.
** Copyright (C) 2001 Marc Norton
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
*   ksearch.h
*
*   Trie based multi-pattern matcher
*/

#ifndef SFKSEARCH_H
#define SFKSEARCH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define ALPHABET_SIZE 256

#define KTRIEMETHOD_STD 0
#define KTRIEMETHOD_QUEUE 1

/*
*
*/
typedef struct _ktriepattern {

  struct  _ktriepattern* next;  /* global list of all patterns*/
  struct  _ktriepattern* mnext;  /* matching list of duplicate keywords*/

  unsigned char* P;    /* no case*/
  unsigned char* Pcase; /* case sensitive*/
  int             n;
  int             nocase;
  int             negative;
  void         * id;
  void         * rule_option_tree;
  void         * neg_list;

} KTRIEPATTERN;


/*
*
*/
typedef struct _ktrienode {

  int     edge; /* character*/

  struct  _ktrienode* sibling;
  struct  _ktrienode* child;

  KTRIEPATTERN*pkeyword;

} KTRIENODE;


#define KTRIE_ROOT_NODES     256

#define SFK_MAX_INQ 32
typedef struct
{
    unsigned inq;
    unsigned inq_flush;
    void* q[SFK_MAX_INQ];
} SFK_PMQ;

/*
*
*/
typedef struct {

  KTRIEPATTERN* patrn; /* List of patterns, built as they are added*/


  KTRIENODE   * root[KTRIE_ROOT_NODES];  /* KTrie nodes*/

  int            memory;
  int            nchars;
  int            npats;
  int            duplicates;
  int            method;
  int            end_states; /* should equal npats - duplicates*/

  int            bcSize;
  unsigned short bcShift[KTRIE_ROOT_NODES];
  void           (*userfree)(void*p);
  void           (*optiontreefree)(void**p);
  void           (*neg_list_free)(void**p);
  SFK_PMQ        q;

} KTRIE_STRUCT;

void KTrie_init_xlatcase();

KTRIE_STRUCT* KTrieNew(
    int method, void (*userfree)(void*p),
    void (*optiontreefree)(void**p),
    void (*neg_list_free)(void**p));

int KTrieAddPattern(
    KTRIE_STRUCT*ts, unsigned char* P, int n,
    int nocase, int negative, void* id );

int KTrieCompile(
    KTRIE_STRUCT* ts,
    int (*build_tree)(void* id, void**existing_tree),
    int (*neg_list_func)(void*id, void**list));

struct SnortConfig;

int KTrieCompileWithSnortConf(
    SnortConfig*, KTRIE_STRUCT* ts,
    int (*build_tree)(SnortConfig*, void* id, void**existing_tree),
    int (*neg_list_func)(void*id, void**list));

int KTrieSearch(
    KTRIE_STRUCT* ts, unsigned char* T,  int n,
    int(*match)(void* id, void*tree, int index, void*data, void*neg_list),
    void*data );

int KTrieSearchQ(
    KTRIE_STRUCT* ts, unsigned char* T,  int n,
    int(*match)(void* id, void*tree, int index, void*data, void*neg_list),
    void*data );

unsigned int KTrieMemUsed(void);
void KTrieInitMemUsed(void);
void KTrieDelete(KTRIE_STRUCT*k);
int  KTriePatternCount(KTRIE_STRUCT*k);

void sfksearch_print_qinfo(void);

#endif
