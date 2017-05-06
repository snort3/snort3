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

/*
*
*  sfghash.c
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

#include "sfghash.h"

#include <cassert>

#include "utils/util.h"

#include "sfhashfcn.h"
#include "sfprimetable.h"

/*
*
*    Create a new hash table
*
*    nrows    : number of rows in hash table, primes are best.
*               > 0  => we use the nearest prime internally
*               < 0  => we use the magnitude as nrows.
*    keysize  : > 0 => bytes in each key, keys are binary bytes,
*               all keys are the same size.
*               ==0 => keys are strings and are null terminated,
*               allowing random key lengths.
*    userkeys : > 0 => indicates user owns the key data
*               and we should not allocate or free space for it,
*               nor should we attempt to free the user key. We just
*               save the pointer to the key.
*               ==0 => we should copy the keys and manage them internally
*    userfree : routine to free users data, null if we should not
*               free user data in sfghash_delete(). The routine
*               should be of the form 'void userfree(void * userdata)',
*               'free' works for simple allocations.
*/
SFGHASH* sfghash_new(int nrows, int keysize, int userkeys, SfgHashFree userfree)
{
    if ( nrows > 0 ) /* make sure we have a prime number */
    {
        nrows = sf_nearest_prime(nrows);
    }
    else  /* use the magnitude or nrows as is */
    {
        nrows = -nrows;
    }

    SFGHASH* h = (SFGHASH*)snort_calloc(sizeof(SFGHASH));

    h->sfhashfcn = sfhashfcn_new(nrows);
    h->table = (SFGHASH_NODE**)snort_calloc(nrows, sizeof(SFGHASH_NODE*));

    for ( int i = 0; i < nrows; i++ )
    {
        h->table[i] = 0;
    }

    h->userkey = userkeys;
    h->keysize = keysize;
    h->nrows = nrows;
    h->count = 0;
    h->userfree = userfree;

    h->crow = 0; // findfirst/next current row
    h->cnode = 0; // findfirst/next current node ptr

    return h;
}

/*
*  Delete the hash Table
*
*  free key's, free node's, and free the users data, if they
*  supply a free function
*/
void sfghash_delete(SFGHASH* h)
{
    int i;
    SFGHASH_NODE* node, * onode;

    if ( !h )
        return;

    sfhashfcn_free(h->sfhashfcn);

    if ( h->table )
    {
        for (i=0; i<h->nrows; i++)
        {
            for ( node=h->table[i]; node; )
            {
                onode = node;
                node  = node->next;

                if ( !h->userkey && onode->key )
                    snort_free((void*)onode->key);

                if ( h->userfree && onode->data )
                    h->userfree(onode->data); /* free users data, with users function */

                snort_free(onode);
            }
        }
        snort_free(h->table);
        h->table = 0;
    }

    snort_free(h);
}

/*
*  Add a key + data pair
*  ---------------------
*
*  key + data should both be non-zero, although data can be zero
*
*  t    - hash table
*  key  - users key data (should be unique in this table)
*         may be ascii strings or fixed size binary keys
*  data - users data pointer
*
*  returns  SF_HASH_NOMEM: alloc error
*           SF_HASH_INTABLE : key already in table (t->cnode points to the node)
*           SF_OK: added a node for this key + data pair
*
*  Notes:
*  If the key node already exists, then t->cnode points to it on return,
*  this allows you to do something with the node - like add the data to a
*  linked list of data items held by the node, or track a counter, or whatever.
*
*/
int sfghash_add(SFGHASH* t, const void* const key, void* const data)
{
    unsigned hashkey;
    int klen;
    int index;
    SFGHASH_NODE* hnode;

    if (t == nullptr || key == nullptr)
        return SFGHASH_ERR;

    /*
    *   Get proper Key Size
    */
    if ( t->keysize > 0  )
    {
        klen = t->keysize;
    }
    else
    {
        /* need the null byte for strcmp() in sfghash_find() */
        klen = strlen( (char*)key) + 1;
    }

    hashkey = t->sfhashfcn->hash_fcn(t->sfhashfcn, (unsigned char*)key, klen);

    index = hashkey % t->nrows;

    /*
    *  Uniqueness:
    *  Check 1st to see if the key is already in the table
    *  Just bail if it is.
    */
    for ( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if ( t->keysize > 0 )
        {
            if ( !t->sfhashfcn->keycmp_fcn(hnode->key,key,klen) )
            {
                t->cnode = hnode; /* save pointer to the node */
                return SFGHASH_INTABLE; /* found it */
            }
        }
        else
        {
            if ( !strcmp((const char*)hnode->key,(const char*)key) )
            {
                t->cnode = hnode; /* save pointer to the node */
                return SFGHASH_INTABLE; /* found it */
            }
        }
    }

    /*
    *  Create new node
    */
    hnode = (SFGHASH_NODE*)snort_calloc(sizeof(SFGHASH_NODE));

    /* Add the Key */
    if ( t->userkey )
    {
        /* Use the Users key */
        hnode->key = key;
    }
    else
    {
        /* Create new key */
        hnode->key = snort_alloc(klen);

        /* Copy key  */
        memcpy((void*)hnode->key,key,klen);
    }

    /* Add The Node */
    if ( t->table[index] ) /* add the node to the existing list */
    {
        hnode->prev = 0;  // insert node as head node
        hnode->next=t->table[index];
        hnode->data=data;
        t->table[index]->prev = hnode;
        t->table[index] = hnode;
    }
    else /* 1st node in this list */
    {
        hnode->prev=0;
        hnode->next=0;
        hnode->data=data;
        t->table[index] = hnode;
    }

    t->count++;

    return SFGHASH_OK;
}

/*
*  Find a Node based on the key, return users data.
*/
static SFGHASH_NODE* sfghash_find_node(SFGHASH* t, const void* const key)
{
    unsigned hashkey;
    int index, klen;
    SFGHASH_NODE* hnode;

    assert(t);

    if ( t->keysize  )
    {
        klen = t->keysize;
    }
    else
    {
        klen = strlen( (char*)key) + 1;
    }

    hashkey = t->sfhashfcn->hash_fcn(t->sfhashfcn, (unsigned char*)key, klen);

    index = hashkey % t->nrows;

    for ( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if ( t->keysize == 0 )
        {
            if ( !strcmp((char*)hnode->key,(char*)key) )
            {
                return hnode;
            }
        }
        else
        {
            if ( !t->sfhashfcn->keycmp_fcn(hnode->key,key,t->keysize) )
            {
                return hnode;
            }
        }
    }

    return NULL;
}

/*
*  Find a Node based on the key, return users data.
*/
void* sfghash_find(SFGHASH* t, const void* const key)
{
    SFGHASH_NODE* hnode;

    assert(t);

    hnode = sfghash_find_node(t, key);

    if ( hnode )
        return hnode->data;

    return NULL;
}

/*
*  Unlink and free the node
*/
static int sfghash_free_node(SFGHASH* t, unsigned index, SFGHASH_NODE* hnode)
{
    assert(t);

    if ( !t->userkey && hnode->key )
        snort_free((void*)hnode->key);

    hnode->key = 0;

    if ( t->userfree)
        t->userfree(hnode->data);  /* free users data, with users function */

    if ( hnode->prev )  // not the 1st node
    {
        hnode->prev->next = hnode->next;
        if ( hnode->next )
            hnode->next->prev = hnode->prev;
    }
    else if ( t->table[index] )  // 1st node
    {
        t->table[index] = t->table[index]->next;
        if ( t->table[index] )
            t->table[index]->prev = 0;
    }

    snort_free(hnode);

    t->count--;

    return SFGHASH_OK;
}

/*
*  Remove a Key/Data Pair from the table - find it, unlink it, and free the memory for it.
*
*  returns : 0 - OK
*           -1 - node not found
*/
int sfghash_remove(SFGHASH* t, const void* const key)
{
    SFGHASH_NODE* hnode;
    int klen;
    unsigned hashkey, index;

    assert(t);

    if ( t->keysize > 0 )
    {
        klen = t->keysize;
    }
    else
    {
        klen = strlen((char*)key) + 1;
    }

    hashkey = t->sfhashfcn->hash_fcn(t->sfhashfcn, (unsigned char*)key, klen);

    index = hashkey % t->nrows;

    for ( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if ( t->keysize > 0 )
        {
            if ( !t->sfhashfcn->keycmp_fcn(hnode->key,key,klen) )
            {
                return sfghash_free_node(t, index, hnode);
            }
        }
        else
        {
            if ( !strcmp((const char*)hnode->key,(const char*)key) )
            {
                return sfghash_free_node(t, index, hnode);
            }
        }
    }

    return SFGHASH_ERR;
}

/* Internal use only */
static void sfghash_next(SFGHASH* t)
{
    assert(t and t->cnode);

    /* Next node in current node list */
    t->cnode = t->cnode->next;
    if ( t->cnode )
    {
        return;
    }

    /* Next row
       Get 1st node in next non-empty row/node list */
    for ( t->crow++; t->crow < t->nrows; t->crow++ )
    {
        t->cnode = t->table[ t->crow ];
        if ( t->cnode )
        {
            return;
        }
    }
}

/*
*   Get First Hash Table Node
*/
SFGHASH_NODE* sfghash_findfirst(SFGHASH* t)
{
    SFGHASH_NODE* n;

    assert(t);
    /* Start with 1st row */
    for ( t->crow=0; t->crow < t->nrows; t->crow++ )
    {
        /* Get 1st Non-Null node in row list */
        t->cnode = t->table[ t->crow ];

        if ( t->cnode )
        {
            n = t->cnode;

            sfghash_next(t); // load t->cnode with the next entry

            return n;
        }
    }
    return NULL;
}

/*
*   Get Next Hash Table Node
*/
SFGHASH_NODE* sfghash_findnext(SFGHASH* t)
{
    SFGHASH_NODE* n;

    assert(t);

    n = t->cnode;

    if ( !n ) /* Done, no more entries */
    {
        return NULL;
    }

    /*
       Preload next node into current node
    */
    sfghash_next(t);

    return n;
}

/**
 * Make sfhashfcn use a separate set of opcodes for the backend.
 *
 * @param h sfhashfcn ptr
 * @param hash_fcn user specified hash function
 * @param keycmp_fcn user specified key comparison function
 */
int sfghash_set_keyops(SFGHASH* h,
    unsigned (* hash_fcn)(SFHASHFCN* p, unsigned char* d, int n),
    int (* keycmp_fcn)(const void* s1, const void* s2, size_t n))
{
    assert(h && hash_fcn && keycmp_fcn);

    return sfhashfcn_set_keyops(h->sfhashfcn, hash_fcn, keycmp_fcn);
}
