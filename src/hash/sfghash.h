//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// sfghash.h author Marc Norton

#ifndef SFGHASH_H
#define SFGHASH_H

// generic hash table - stores and maps key + data pairs

#include "main/snort_types.h"

struct SFHASHFCN;

#define SFGHASH_NOMEM    -2
#define SFGHASH_ERR      -1
#define SFGHASH_OK        0
#define SFGHASH_INTABLE   1

// Flags for ghash_new: userkeys
#define GH_COPYKEYS 0
#define GH_USERKEYS 1

struct SFGHASH_NODE
{
    struct SFGHASH_NODE* next, * prev;

    const void* key;  /* Copy of, or Pointer to, the Users key */
    void* data;       /* The users data, this is never copied! */
};

typedef void (* SfgHashFree)(void*);

struct SFGHASH
{
    SFHASHFCN* sfhashfcn;
    int keysize;          /* bytes in key, if < 0 -> keys are strings */
    int userkey;          /* user owns the key */

    SFGHASH_NODE** table; /* array of node ptr's */
    int nrows;            /* # rows int the hash table use a prime number 211, 9871 */

    unsigned count;       /* total # nodes in table */

    SfgHashFree userfree;

    int crow;             /* findfirst/next row in table */
    SFGHASH_NODE* cnode;  /* findfirst/next node ptr */
};

SO_PUBLIC SFGHASH* sfghash_new(int nrows, int keysize, int userkeys, SfgHashFree);
SO_PUBLIC void sfghash_delete(SFGHASH*);
SO_PUBLIC int sfghash_add(SFGHASH*, const void* const key, void* const data);
SO_PUBLIC int sfghash_remove(SFGHASH*, const void* const key);
SO_PUBLIC void* sfghash_find(SFGHASH*, const void* const key);
SO_PUBLIC SFGHASH_NODE* sfghash_findfirst(SFGHASH*);
SO_PUBLIC SFGHASH_NODE* sfghash_findnext(SFGHASH*);
SO_PUBLIC int sfghash_set_keyops(SFGHASH*,
    unsigned (* hash_fcn)(SFHASHFCN* p, unsigned char* d, int n),
    int (* keycmp_fcn)(const void* s1, const void* s2, size_t n));

#endif

