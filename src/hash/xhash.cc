//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
/* xhash.cc
 *
 *  A Customized hash table library for storing and accessing key + data pairs.
 *
 *  This table incorporates a memory manager (memcap.c) to provide a memory cap,
 *  and an automatic node recovery system for out of memory management. Keys and
 *  Data are copied into the hash table during the add operation. The data may
 *  be allocated and freed by the user (by setting the datasize to zero ). A
 *  user callback is provided to allow the user to do cleanup whenever a node
 *  is released, by either the ANR system or the release() function.
 *
 *  Users can and should delete nodes when they know they are not needed anymore,
 *  but this custom table is designed for the case where nodes are allocated
 *  permanently, we have to limit memory, and we wish to recycle old nodes.
 *  Many problems have a natural node aging paradigm working in our favor,
 *  so automated node aging makes sense. i.e. thresholding, tcp state.
 *
 *  This hash table maps keys to data.  All keys must be unique.
 *  Uniqueness is enforced by the code.
 *
 *  Features:
 *
 *    1) Keys must be fixed length (per table) binary byte sequences.
 *         keys are copied during the add function
 *    2) Data must be fixed length (per table) binary byte sequences.
 *         data is copied during the add function - if datasize > 0
 *       Data may be managed by the user as well.
 *    3) Table row sizes can be automatically adjusted to
 *       the nearest prime number size during table initialization/creation.
 *    4) Memory management includes tracking the size of each allocation,
 *       number of allocations, enforcing a memory cap, and automatic node
 *       recovery - when  memory is low the oldest untouched node
 *       is unlinked and recycled for use as a new node.
 *
 *  Per Node Memory Usage:
 *  ----------------------
 *     HashNode bytes
 *     KEYSIZE bytes
 *     [DATASIZE bytes] if datasize > 0 during call to xhash_new.
 *
 *  The hash node memory (xhash_node,key,and data) is allocated with
 *  one call to s_alloc/memcap_alloc.
 *
 *  Author: Marc Norton
 *
 *  2003-06-03: cmg - added xhash_{l,m}ru to return {least,most}
 *              recently used node from the global list
 *
 *              - added _anrcount function
 *              - changed count function to return unsigned to match structure
 *
 *  2003-06-11: cmg added
 *              overhead_bytes + blocks to separate out the
 *              memcap constraints from the hash table itself
 *              find success v fail
 *
 *  2003-06-19: cmg added
 *
 *              ability to set own hash function
 *              ability to set own key cmp function
 *
 *  2003-06-30: rdempster
 *              fixed bug in that would anr from the freelist
 *
 *  2005-11-15: modified xhash_add to check if 'data' is zero before memcpy'ing.
 *              this allows user to pass null for data, and set up the data area
 *              themselves after the call - this is much more flexible.
 *  8/31/2006: man - changed to use prime table lookup.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "xhash.h"

#include <cassert>
#include "utils/util.h"

using namespace snort;

namespace snort
{

XHash::XHash(int nrows_, int keysize_, int datasize_, unsigned long maxmem,
    bool anr_enabled, Hash_FREE_FCN anr_free, Hash_FREE_FCN usr_free,
    bool recycle_nodes)
    : keysize(keysize_), datasize(datasize_), recycle_nodes(recycle_nodes),
      anr_enabled(anr_enabled), anr_free(anr_free), usr_free(usr_free)
{
    // adjust rows to be power of 2
    if ( nrows_ > 0 )
        nrows = hash_nearest_power_of_2(nrows_);
    else
        nrows = -nrows_;       // if negative use as is

    table = (HashNode**)snort_calloc(sizeof(HashNode*) * nrows);
    hashfcn = hashfcn_new(nrows);
    sfmemcap_init(&mc, maxmem);

    for ( unsigned i = 0; i < nrows; i++ )
        table[i] = nullptr;

    mem_allocated_per_entry = sizeof(HashNode) + keysize + datasize + sizeof(long);
}

XHash::~XHash()
{
    if ( hashfcn )
        hashfcn_free(hashfcn);

    for (unsigned i = 0; i < nrows; i++)
    {
        for ( HashNode* node = table[i]; node; )
        {
            HashNode* onode = node;
            node  = node->next;

            if ( usr_free )
                usr_free(onode->key, onode->data);

            sfmemcap_free(&mc, onode);
        }
    }
    snort_free(table);
    purge_free_list();
}

void XHash::clear()
{
    for (unsigned i = 0; i < nrows; i++)
    {
        HashNode* n = table[i];
        while ( n )
        {
            HashNode* tmp;
            tmp = n;
            n = n->next;
            release_node(tmp);
        }
    }

    max_nodes = 0;
    crow = 0;
    cnode = nullptr;
    count = 0;
    ghead = nullptr;
    gtail = nullptr;
    anr_count = 0;
    anr_tries = 0;
    find_success = 0;
    find_fail = 0;
}

void XHash::save_free_node(HashNode* hnode)
{
    if ( fhead )
    {
        hnode->gprev    = nullptr;
        hnode->gnext    = fhead;
        fhead->gprev = hnode;
        fhead        = hnode;
    }
    else
    {
        hnode->gprev = nullptr;
        hnode->gnext = nullptr;
        fhead    = hnode;
        ftail    = hnode;
    }
}

HashNode* XHash::get_free_node()
{
    HashNode* node = fhead;

    if ( fhead )
    {
        fhead = fhead->gnext;
        if ( fhead )
            fhead->gprev = nullptr;

        if ( ftail == node )
            ftail = nullptr;
    }

    return node;
}

void XHash::purge_free_list()
{
    HashNode* cur = fhead;
    while ( cur )
    {
        HashNode* next = cur->gnext;
        sfmemcap_free(&mc, (void*)cur);
        cur = next;
    }

    fhead = nullptr;
    ftail = nullptr;
}

void XHash::glink_node(HashNode* hnode)
{
    if ( ghead )
    {
        hnode->gprev = nullptr;
        hnode->gnext = ghead;
        ghead->gprev = hnode;
        ghead = hnode;
    }
    else
    {
        hnode->gprev = nullptr;
        hnode->gnext = nullptr;
        ghead = hnode;
        gtail = hnode;
    }
}

void XHash::gunlink_node(HashNode* hnode)
{
    if ( gnode == hnode )
        gnode = hnode->gnext;

    if ( ghead == hnode )
    {
        ghead = ghead->gnext;
        if ( ghead )
            ghead->gprev = nullptr;
    }

    if ( hnode->gprev )
        hnode->gprev->gnext = hnode->gnext;
    if ( hnode->gnext )
        hnode->gnext->gprev = hnode->gprev;

    if ( gtail == hnode )
        gtail = hnode->gprev;
}

void XHash::gmove_to_front(HashNode* hnode)
{
    if ( hnode != ghead )
    {
        gunlink_node(hnode);
        glink_node(hnode);
    }
}

HashNode* XHash::gfind_next()
{
    HashNode* n = gnode;
    if ( n )
        gnode = n->gnext;
    return n;
}

HashNode* XHash::gfind_first()
{
    if ( ghead )
        gnode = ghead->gnext;
    else
        gnode = nullptr;
    return ghead;
}

void* XHash::get_mru_user_data()
{
    if ( ghead )
        return ghead->data;
    else
        return nullptr;
}

void* XHash::get_lru_user_data()
{
    if ( gtail )
        return gtail->data;
    else
        return nullptr;
}

void XHash::link_node(HashNode* hnode)
{
    if ( table[hnode->rindex] )
    {
        hnode->prev = nullptr;
        hnode->next = table[hnode->rindex];
        table[hnode->rindex]->prev = hnode;
        table[hnode->rindex] = hnode;
    }
    else
    {
        hnode->prev = nullptr;
        hnode->next = nullptr;
        table[hnode->rindex] = hnode;
    }
}

void XHash::unlink_node(HashNode* hnode)
{
    if ( hnode->prev )
    {
        hnode->prev->next = hnode->next;
        if ( hnode->next )
            hnode->next->prev = hnode->prev;
    }
    else if ( table[hnode->rindex] )
    {
        table[hnode->rindex] = table[hnode->rindex]->next;
        if ( table[hnode->rindex] )
            table[hnode->rindex]->prev = nullptr;
    }
}

void XHash::move_to_front(HashNode* n)
{
    if ( table[n->rindex] != n )
    {
        unlink_node(n);
        link_node(n);
    }

    if (n == gnode)
        gnode = n->gnext;
    gmove_to_front(n);
}

/*
 * Allocate a new hash node, uses Auto Node Recovery if needed and enabled.
 *
 * The oldest node is the one with the longest time since it was last touched,
 * and does not have any direct indication of how long the node has been around.
 * We don't monitor the actual time since last being touched, instead we use a
 * splayed global list of node pointers. As nodes are accessed they are splayed
 * to the front of the list. The oldest node is just the tail node.
 *
 */
HashNode* XHash::allocate_node()
{
    // use previously allocated node if there is a free one...
    HashNode* hnode = get_free_node();
    if ( !hnode )
    {
        if ( (max_nodes == 0) || (count < max_nodes) )
            hnode = (HashNode*)sfmemcap_alloc(&mc,
                sizeof(HashNode) + keysize + datasize);

        if ( !hnode && anr_enabled && gtail )
        {
            /* Find the oldest node the users willing to let go. */
            for (hnode = gtail; hnode; hnode = hnode->gprev )
            {
                if ( anr_free )
                {
                    anr_tries++;
                    if ( anr_free(hnode->key, hnode->data) )
                        continue;   // don't recycle this one...
                }

                gunlink_node(hnode);
                unlink_node(hnode);
                count--;
                anr_count++;
                break;
            }
        }
    }

    return hnode;
}

HashNode* XHash::find_node_row(const void* key, int* rindex)
{
    unsigned hashkey = hashfcn->hash_fcn(hashfcn, (const unsigned char*)key, keysize);

    // Modulus is slow. masking since table size is a power of 2.
    int index  = hashkey & (nrows - 1);
    *rindex = index;

    for (HashNode* hnode = table[index]; hnode; hnode = hnode->next )
    {
        if ( hashfcn->keycmp_fcn(hnode->key, key, keysize) )
        {
            if ( splay > 0 )
                move_to_front(hnode);

            find_success++;
            return hnode;
        }
    }

    find_fail++;
    return nullptr;
}

int XHash::insert(const void* key, void* data)
{
    assert(key);

    int index = 0;

    /* Enforce uniqueness: Check for the key in the table */
    HashNode* hnode = find_node_row(key, &index);
    if ( hnode )
    {
        cnode = hnode;
        return HASH_INTABLE;
    }

    hnode = allocate_node();
    if ( !hnode )
        return HASH_NOMEM;

    hnode->key = (char*)hnode + sizeof(HashNode);
    memcpy(hnode->key, key, keysize);
    hnode->rindex = index;

    if ( datasize )
    {
        hnode->data = (char*)hnode + sizeof(HashNode) + keysize;
        if ( data )
            memcpy(hnode->data, data, datasize);
    }
    else
        hnode->data = data;

    link_node (hnode);
    glink_node(hnode);
    count++;

    return HASH_OK;
}

HashNode* XHash::get_node(const void* key)
{
    assert(key);

    int index = 0;

    // Enforce uniqueness: Check for the key in the table
    HashNode* hnode = find_node_row( key, &index);
    if ( hnode )
    {
        cnode = hnode;
        return hnode;
    }

    hnode = allocate_node();
    if ( !hnode )
        return nullptr;

    hnode->key = (char*)hnode + sizeof(HashNode);
    memcpy(hnode->key, key, keysize);
    hnode->rindex = index;

    if ( datasize )
        hnode->data = (char*)hnode + sizeof(HashNode) + keysize;
    else
        hnode->data = nullptr;

    link_node(hnode);
    glink_node(hnode);
    count++;

    return hnode;
}

HashNode* XHash::get_node_with_prune(const void* key, bool* prune_performed)
{
    assert(key);

    size_t mem_after_alloc = mc.memused + mem_allocated_per_entry;
    bool over_capacity = (mc.memcap < mem_after_alloc);

    if ( over_capacity )
        *prune_performed = (delete_anr_or_lru_node() == HASH_OK);

    HashNode* hnode = nullptr;
    if ( *prune_performed or !over_capacity )
        hnode = get_node(key);

    return hnode;
}

HashNode* XHash::find_node(const void* key)
{
    assert(key);

    int rindex = 0;
    return find_node_row(key, &rindex);
}

void* XHash::get_user_data(void* key)
{
    assert(key);

    int rindex = 0;
    HashNode* hnode = find_node_row(key, &rindex);
    if ( hnode )
        return hnode->data;

    return nullptr;
}

int XHash::release_node(HashNode* hnode)
{
    assert(hnode);

    unlink_node(hnode);
    gunlink_node(hnode);
    count--;

    if ( usr_free )
        usr_free(hnode->key, hnode->data);

    if ( recycle_nodes )
        save_free_node(hnode);
    else
        sfmemcap_free(&mc, hnode);

    return HASH_OK;
}

int XHash::release_node(void* key)
{
    assert(key);

    unsigned hashkey = hashfcn->hash_fcn(hashfcn, (unsigned char*)key, keysize);

    unsigned index = hashkey & (nrows - 1);
    for ( HashNode* hnode = table[index]; hnode; hnode = hnode->next )
    {
        if ( hashfcn->keycmp_fcn(hnode->key, key, keysize) )
            return release_node(hnode);
    }

    return HASH_ERR;
}

int XHash::delete_free_node()
{
    HashNode* fn = get_free_node();
    if (fn)
    {
        sfmemcap_free(&mc, fn);
        return HASH_OK;
    }
    return HASH_ERR;
}

int XHash::delete_anr_or_lru_node()
{
    if ( fhead )
    {
        if (delete_free_node() == HASH_OK)
            return HASH_OK;
    }

    if ( gtail )
    {
        if ( release_node(gtail) == HASH_OK )
        {
            if ( fhead )
            {
                if ( delete_free_node() == HASH_OK )
                    return HASH_OK;
            }
            else if ( !recycle_nodes )
                return HASH_OK;
        }
    }
    return HASH_ERR;
}

int XHash::free_over_allocations(unsigned work_limit, unsigned* num_freed)
{

    while (mc.memcap < mc.memused and work_limit--)
    {
        if (delete_anr_or_lru_node() != HASH_OK)
            return HASH_ERR;

        ++*num_freed;
    }

    return (mc.memcap >= mc.memused) ? HASH_OK : HASH_PENDING;
}

void XHash::update_cnode()
{
    if ( !cnode )
        return;

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

HashNode* XHash::find_first_node()
{
    for ( crow = 0; crow < nrows; crow++ )
    {
        cnode = table[crow];
        if ( cnode )
        {
            HashNode* n = cnode;
            update_cnode();
            return n;
        }
    }

    return nullptr;
}

HashNode* XHash::find_next_node()
{
    HashNode* n = cnode;
    if ( !n )
        return nullptr;

    update_cnode();

    return n;
}

void XHash::set_key_opcodes(hash_func hash_fcn, keycmp_func keycmp_fcn)
{
    hashfcn_set_keyops(hashfcn, hash_fcn, keycmp_fcn);
}

} // namespace snort
