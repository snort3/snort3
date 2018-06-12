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

// xhash.h author Marc Norton

#ifndef XHASH_H
#define XHASH_H

// generic hash table - stores and maps key + data pairs
// (supports memcap and automatic memory recovery when out of memory)

#include "utils/sfmemcap.h"
#include "main/snort_types.h"

struct HashFnc;

namespace snort
{
#define XHASH_NOMEM    (-2)
#define XHASH_ERR      (-1)
#define XHASH_OK        0
#define XHASH_INTABLE   1

struct XHashNode
{
    struct XHashNode* gnext; // global node list - used for aging nodes
    struct XHashNode* gprev;
    struct XHashNode* next;  // row node list
    struct XHashNode* prev;

    int rindex;  // row index of table this node belongs to.

    void* key;  // Pointer to the key.
    void* data; // Pointer to the users data, this is not copied !
};

typedef int (* XHash_FREE_FCN)(void* key, void* data);

struct XHash
{
    HashFnc* hashfcn;    // hash function
    int keysize;             // bytes in key, if <= 0 -> keys are strings
    int datasize;            // bytes in key, if == 0 -> user data
    XHashNode** table;    // array of node ptr's */
    unsigned nrows;          // # rows int the hash table use a prime number 211, 9871
    unsigned count;          // total # nodes in table

    unsigned crow;           // findfirst/next row in table
    unsigned pad;
    XHashNode* cnode;     // findfirst/next node ptr
    int splay;               // whether to splay nodes with same hash bucket

    unsigned max_nodes;      // maximum # of nodes within a hash
    MEMCAP mc;
    unsigned overhead_bytes;  // # of bytes that will be unavailable for nodes inside the
                              // table
    unsigned overhead_blocks; // # of blocks consumed by the table
    unsigned find_fail;
    unsigned find_success;

    XHashNode* ghead, * gtail;  // global - root of all nodes allocated in table
    XHashNode* fhead, * ftail;  // list of free nodes, which are recycled
    XHashNode* gnode;           // gfirst/gnext node ptr */
    int recycle_nodes;             // recycle nodes. Nodes are not freed, but are used for
                                   // subsequent new nodes

    /* Automatic Node Recover (ANR): When number of nodes in hash is equal
     * to max_nodes, remove the least recently used nodes and use it for
     * the new node. anr_tries indicates # of ANR tries.*/

    unsigned anr_tries;
    unsigned anr_count;      // # ANR ops performed
    int anr_flag;            // 0=off, !0=on

    XHash_FREE_FCN anrfree;
    XHash_FREE_FCN usrfree;
};

SO_PUBLIC XHash* xhash_new(int nrows, int keysize, int datasize, unsigned long memcap,
    int anr_flag,
    XHash_FREE_FCN anrfunc,
    XHash_FREE_FCN usrfunc,
    int recycle_flag);

SO_PUBLIC void xhash_set_max_nodes(XHash* h, int max_nodes);

SO_PUBLIC void xhash_delete(XHash* h);
SO_PUBLIC int xhash_make_empty(XHash*);

SO_PUBLIC int xhash_add(XHash* h, void* key, void* data);
SO_PUBLIC XHashNode* xhash_get_node(XHash* t, const void* key);
SO_PUBLIC int xhash_remove(XHash* h, void* key);

//  Get the # of Nodes in HASH the table
inline unsigned xhash_count(XHash* t)
{ return t->count; }

//  Get the # auto recovery
inline unsigned xhash_anr_count(XHash* t)
{ return t->anr_count; }

//  Get the # finds
inline unsigned xhash_find_total(XHash* t)
{ return t->find_success + t->find_fail; }

//  Get the # unsuccessful finds
inline unsigned xhash_find_fail(XHash* t)
{ return t->find_fail; }

//  Get the # successful finds
inline unsigned xhash_find_success(XHash* t)
{ return t->find_success; }

//  Get the # of overhead bytes
inline unsigned xhash_overhead_bytes(XHash* t)
{ return t->overhead_bytes; }

// Get the # of overhead blocks
inline unsigned xhash_overhead_blocks(XHash* t)
{ return t->overhead_blocks; }

SO_PUBLIC void* xhash_mru(XHash* t);
SO_PUBLIC void* xhash_lru(XHash* t);
SO_PUBLIC void* xhash_find(XHash* h, void* key);
SO_PUBLIC XHashNode* xhash_find_node(XHash* t, const void* key);

SO_PUBLIC XHashNode* xhash_findfirst(XHash* h);
SO_PUBLIC XHashNode* xhash_findnext(XHash* h);

SO_PUBLIC XHashNode* xhash_ghead(XHash* h);
SO_PUBLIC void xhash_gmovetofront(XHash* t, XHashNode* hnode);

SO_PUBLIC int xhash_free_node(XHash* t, XHashNode* node);

typedef uint32_t (* hash_func)(HashFnc*, const unsigned char* d, int n);

// return 0 for ==, 1 for != ; FIXIT-L convert to bool
typedef int (* keycmp_func)(const void* s1, const void* s2, size_t n);

SO_PUBLIC void xhash_set_keyops(XHash* h, hash_func, keycmp_func);

SO_PUBLIC XHashNode* xhash_gfindfirst(XHash* t);
SO_PUBLIC XHashNode* xhash_gfindnext(XHash* t);
} // namespace snort
#endif

