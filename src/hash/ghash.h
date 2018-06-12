//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// ghash.h author Marc Norton

#ifndef GHASH_H
#define GHASH_H

// generic hash table - stores and maps key + data pairs

#include "main/snort_types.h"

struct HashFnc;

namespace snort
{

#define GHASH_NOMEM    (-2)
#define GHASH_ERR      (-1)
#define GHASH_OK        0
#define GHASH_INTABLE   1

// Flags for ghash_new: userkeys
#define GH_COPYKEYS 0
#define GH_USERKEYS 1

struct GHashNode
{
    struct GHashNode* next, * prev;

    const void* key;  /* Copy of, or Pointer to, the Users key */
    void* data;       /* The users data, this is never copied! */
};

typedef void (* gHashFree)(void*);

struct GHash
{
    HashFnc* hashfcn;
    int keysize;          /* bytes in key, if < 0 -> keys are strings */
    int userkey;          /* user owns the key */

    GHashNode** table; /* array of node ptr's */
    int nrows;            /* # rows int the hash table use a prime number 211, 9871 */

    unsigned count;       /* total # nodes in table */

    gHashFree userfree;

    int crow;             /* findfirst/next row in table */
    GHashNode* cnode;  /* findfirst/next node ptr */
};

SO_PUBLIC GHash* ghash_new(int nrows, int keysize, int userkeys, gHashFree);
SO_PUBLIC void ghash_delete(GHash*);
SO_PUBLIC int ghash_add(GHash*, const void* const key, void* const data);
SO_PUBLIC int ghash_remove(GHash*, const void* const key);
SO_PUBLIC void* ghash_find(GHash*, const void* const key);
SO_PUBLIC GHashNode* ghash_findfirst(GHash*);
SO_PUBLIC GHashNode* ghash_findnext(GHash*);
SO_PUBLIC int ghash_set_keyops(GHash*,
unsigned (* hash_fcn)(HashFnc* p, const unsigned char* d, int n),
int (* keycmp_fcn)(const void* s1, const void* s2, size_t n));
}
#endif

