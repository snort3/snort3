//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

/*
*
*  ghash.c
*
*  Generic hash table library.
*
*  This hash table maps unique keys to void data pointers.
*
*  Features:
*    1) Keys may be ascii strings of variable size, or
*       fixed length (per table) binary byte sequences.  This
*       allows use as a Mapping for String+Data pairs, or a
*       generic hashing.
*    2) User can allocate keys, or pass copies and we can
*       allocate space and save keys.
*    3) User can pass a free function to free up user data
*       when the table is deleted.
*    4) Table rows sizes can be automatically adjusted to
*       the nearest prime number size.
*
*  6/10/03 - man - Upgraded the hash function to a Hardened hash function,
*      it has no predictable cycles, and each hash table gets a different
*      randomized hashing function. So even with the source code, you cannot predict
*      anything with this function.  If an attacker can setup a feedback
*      loop he might gain some knowledge of how to muck with us, but even in that case
*      his odds are astronomically skinny.  This is actually the same problem as solved
*      early on with hashing functions where degenerate data with close keys could
*      produce very long bucket chains.
*
*  8/31/06 - man - Added prime tables to speed up prime number lookup.
*
* Author: Marc Norton
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ghash.h"

#include <cassert>

#include "utils/util.h"

#include "hash_defs.h"
#include "primetable.h"

namespace snort
{

GHash::GHash(int nrows_, unsigned keysize, bool userkey, gHashFree userfree)
    : keysize(keysize), userkey(userkey), userfree(userfree)
{
    if ( nrows_ > 0 )
        nrows = nearest_prime(nrows_);
    else
        nrows = -nrows_;

    hashfcn = new HashKeyOperations(nrows);
    table = (GHashNode**)snort_calloc(nrows, sizeof(GHashNode*));
    for ( int i = 0; i < nrows; i++ )
        table[i] = nullptr;

    count = 0;
    crow = 0;
    cnode = nullptr;
}

GHash::~GHash()
{
    for (int i = 0; i < nrows; i++)
        for ( GHashNode* node = table[i]; node; )
        {
            GHashNode* onode = node;
            node  = node->next;

            if ( !userkey && onode->key )
                snort_free(const_cast<void*>(onode->key));

            if ( userfree && onode->data )
                userfree(onode->data);

            snort_free(onode);
        }

    snort_free(table);
    delete hashfcn;
}

GHashNode* GHash::find_node(const void* const key, unsigned index)
{
    assert(key);

    for ( GHashNode* hnode = table[index]; hnode; hnode = hnode->next )
    {
        if ( keysize == 0 )
        {
            if ( !strcmp((const char*)hnode->key, (const char*)key) )
                return hnode;
        }
        else
        {
            if ( hashfcn->key_compare(hnode->key, key, keysize) )
                return hnode;
        }
    }

    return nullptr;
}

int GHash::insert(const void* const key, void* const data)
{
    assert(key && data);

    unsigned index = get_index(key);
    if ( GHashNode* hnode = find_node(key, index) )
    {
        cnode = hnode;
        return HASH_INTABLE;
    }

    GHashNode* hnode = (GHashNode*)snort_calloc(sizeof(GHashNode));
    if ( userkey )
    {
        hnode->key = key;
    }
    else
    {
        unsigned klen = get_key_length(key);
        hnode->key = snort_alloc(klen);
        memcpy(const_cast<void*>(hnode->key), key, klen);
    }

    if ( table[index] )
    {
        hnode->prev = nullptr;
        hnode->next = table[index];
        hnode->data = data;
        table[index]->prev = hnode;
        table[index] = hnode;
    }
    else
    {
        hnode->prev = nullptr;
        hnode->next = nullptr;
        hnode->data = data;
        table[index] = hnode;
    }

    count++;

    return HASH_OK;
}

void* GHash::find(const void* const key)
{
    assert(key);

    unsigned index = get_index(key);
    GHashNode* hnode = find_node(key, index);
    if ( hnode )
        return hnode->data;

    return nullptr;
}

int GHash::free_node(unsigned index, GHashNode* hnode)
{
    assert(hnode);

    if ( !userkey && hnode->key )
        snort_free(const_cast<void*>(hnode->key));

    hnode->key = nullptr;

    if ( userfree)
        userfree(hnode->data);

    if ( hnode->prev )
    {
        hnode->prev->next = hnode->next;
        if ( hnode->next )
            hnode->next->prev = hnode->prev;
    }
    else if ( table[index] )
    {
        table[index] = table[index]->next;
        if ( table[index] )
            table[index]->prev = nullptr;
    }

    snort_free(hnode);
    count--;

    return HASH_OK;
}

int GHash::remove(const void* const key)
{
    assert(key);

    unsigned index = get_index(key);
    if ( GHashNode* hnode = find_node(key, index) )
        return free_node(index, hnode);
    else
        return HASH_NOT_FOUND;
}

void GHash::next()
{
    assert(cnode);

    cnode = cnode->next;
    if ( cnode )
        return;

    for ( crow++; crow < nrows; crow++ )
    {
        cnode = table[crow];
        if ( cnode )
            return;
    }
}

GHashNode* GHash::find_first()
{
    for ( crow = 0; crow < nrows; crow++ )
    {
        cnode = table[crow];
        if ( cnode )
        {
            GHashNode* n = cnode;
            next();
            return n;
        }
    }
    return nullptr;
}

GHashNode* GHash::find_next()
{
    GHashNode* n = cnode;
    if ( n )
        next();

    return n;
}

void GHash::set_hashkey_ops(HashKeyOperations* hk)
{
    delete hashfcn;
    hashfcn = hk;
}

}
