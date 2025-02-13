//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "hash_defs.h"
#include "hash_key_operations.h"
#include "hash_lru_cache.h"

using namespace snort;

namespace snort
{

void XHash::initialize(HashKeyOperations* hk_ops)
{
    hashkey_ops = hk_ops;
    table = (HashNode**)snort_calloc(sizeof(HashNode*) * nrows);

    lru_caches.resize(num_lru_caches);
    for (size_t i = 0; i < num_lru_caches; ++i)
        lru_caches[i] = new HashLruCache();
    
    mem_allocator = new MemCapAllocator(mem_cap, sizeof(HashNode) + keysize + datasize);
}

void XHash::initialize()
{
    initialize(new HashKeyOperations(nrows));
}

void XHash::set_number_of_rows (int rows)
{
    if ( rows > 0 )
        nrows = hash_nearest_power_of_2 (rows);
    else
        nrows = -rows;
}

XHash::XHash(int rows, int keysize, uint8_t num_lru_caches)
    : keysize(keysize), num_lru_caches(num_lru_caches)

{
    set_number_of_rows(rows);
}

XHash::XHash(int rows, int keysize, int datasize, unsigned long memcap, uint8_t num_lru_caches)
    : keysize(keysize), num_lru_caches(num_lru_caches), datasize(datasize), mem_cap(memcap)
{
    assert(num_lru_caches > 0);
    set_number_of_rows(rows);
    initialize();
}

XHash::~XHash()
{
    if ( table )
    {
        for (unsigned i = 0; i < nrows; i++)
            for (HashNode* node = table[i]; node;)
            {
                HashNode* xnode;
                xnode = node;
                node = node->next;
                mem_allocator->free(xnode);
            }

        snort_free(table);
    }

    purge_free_list();
    delete hashkey_ops;
    for (auto lru : lru_caches)
    {
        delete lru;
    }
    delete mem_allocator;
}

void XHash::delete_hash_table()
{
    assert( table );

    for (unsigned i = 0; i < nrows; i++)
        for (HashNode* node = table[i]; node;)
        {
            HashNode* xnode;
            xnode = node;
            node = node->next;
            free_user_data(xnode);
            mem_allocator->free(xnode);
        }

    snort_free(table);
    table = nullptr;
}

void XHash::initialize_node(HashNode *hnode, const void *key, void *data, int index, uint8_t type)
{
    assert(type < num_lru_caches);

    hnode->key = (char*) (hnode) + sizeof(HashNode);
    memcpy(hnode->key, key, keysize);
    if ( datasize )
    {
        hnode->data = (char*) (hnode) + sizeof(HashNode) + keysize;
        if ( data )
            memcpy (hnode->data, data, datasize);
    }
    else
        hnode->data = data;

    hnode->rindex = index;
    link_node(hnode);
    lru_caches[type]->insert(hnode);
}

HashNode* XHash::allocate_node(const void* key, void* data, int index)
{
    // use a free one if available...
    HashNode* hnode = get_free_node();

    // if no free nodes, try to allocate a new one...
    if ( !hnode && ((max_nodes == 0) || (num_nodes < max_nodes)) )
        hnode = (HashNode*)mem_allocator->allocate();

    // if still no node then try to reuse one...
    if ( !hnode && anr_enabled )
        hnode = release_lru_node();

    if ( hnode )
    {
        initialize_node(hnode, key, data, index);
        ++num_nodes;
    }

    return hnode;
}

int XHash::insert(const void* key, void* data)
{
    assert(key);

    int index = 0;
    HashNode* hnode = find_node_row(key, index);
    if ( hnode )
    {
        cursor = hnode;
        return HASH_INTABLE;
    }

    hnode = allocate_node(key, data, index);
    cursor = hnode;
    return ( hnode ) ? HASH_OK : HASH_NOMEM;
}

HashNode* XHash::find_node(const void* key)
{
    assert(key);

    int rindex = 0;
    return find_node_row(key, rindex);
}

HashNode* XHash::find_first_node()
{
    for ( crow = 0; crow < nrows; crow++ )
    {
        cursor = table[crow];
        if ( cursor )
        {
            HashNode* n = cursor;
            update_cursor();
            return n;
        }
    }

    return nullptr;
}

HashNode* XHash::find_next_node()
{
    HashNode* n = cursor;
    if ( !n )
        return nullptr;

    update_cursor();
    return n;
}

void* XHash::get_user_data()
{
    if ( cursor )
        return cursor->data;
    else
        return nullptr;
}

void XHash::update_cursor()
{
    if ( !cursor )
        return;

    cursor = cursor->next;
    if ( cursor )
        return;

    for ( crow++; crow < nrows; crow++ )
    {
        cursor = table[crow];
        if ( cursor )
            return;
    }
}

void* XHash::get_user_data(const void* key, uint8_t type, bool touch)
{
    assert(key);
    assert(type < num_lru_caches);

    int rindex = 0;
    HashNode* hnode = find_node_row(key, rindex, type, touch);
    return ( hnode ) ? hnode->data : nullptr;
}

void XHash::release(uint8_t type)
{
    assert(type < num_lru_caches);
    HashNode* node = lru_caches[type]->get_current_node();
    assert(node);
    release_node(node);
}
int XHash::release_node(HashNode* hnode, uint8_t type)
{
    assert(hnode);
    assert(type < num_lru_caches);

    free_user_data(hnode);
    unlink_node(hnode);
    lru_caches[type]->remove_node(hnode);
    num_nodes--;

    if ( recycle_nodes )
    {
        save_free_node(hnode);
        ++stats.release_recycles;
    }
    else
    {
        mem_allocator->free(hnode);
        ++stats.release_deletes;
    }

    return HASH_OK;
}

int XHash::release_node(const void* key, uint8_t type)
{
    assert(key);
    assert(type < num_lru_caches);

    unsigned hashkey = hashkey_ops->do_hash((const unsigned char*)key, keysize);

    unsigned index = hashkey & (nrows - 1);
    for (HashNode* hnode = table[index]; hnode; hnode = hnode->next)
    {
        if ( hashkey_ops->key_compare(hnode->key, key, keysize) )
            return release_node(hnode, type);
    }

    return HASH_NOT_FOUND;
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

void XHash::move_to_front(HashNode* node,uint8_t type)
{
    assert(type < num_lru_caches);
    if ( table[node->rindex] != node )
    {
        unlink_node(node);
        link_node(node);
    }
    lru_caches[type]->touch(node);
}

void XHash::touch_last_found(uint8_t type)
{
    assert(type < num_lru_caches);
    if ( lfind )
        move_to_front(lfind, type);
}

HashNode* XHash::find_node_row(const void* key, int& rindex, uint8_t type, bool touch)
{
    assert(type < num_lru_caches);
    unsigned hashkey = hashkey_ops->do_hash((const unsigned char*)key, keysize);

    /* Modulus is slow. Switched to a table size that is a power of 2. */
    rindex  = hashkey & (nrows - 1);
    for (HashNode* hnode = table[rindex]; hnode; hnode = hnode->next )
    {
        if ( hashkey_ops->key_compare(hnode->key, key, keysize) )
        {
            lfind = hnode;
            if ( touch )
                move_to_front(hnode, type);
            return hnode;
        }
    }

    return nullptr;
}

void XHash::save_free_node(HashNode* hnode)
{
    if ( fhead )
    {
        hnode->gprev = nullptr;
        hnode->gnext = fhead;
        fhead->gprev = hnode;
        fhead = hnode;
    }
    else
    {
        hnode->gprev = nullptr;
        hnode->gnext = nullptr;
        fhead = hnode;
    }
    ++num_free_nodes;
}

HashNode* XHash::get_free_node()
{
    HashNode* node = fhead;
    if ( fhead )
    {
        fhead = fhead->gnext;
        if ( fhead )
            fhead->gprev = nullptr;
        --num_free_nodes;
    }

    return node;
}

bool XHash::delete_free_node()
{
    HashNode* hnode = get_free_node();
    if ( hnode )
    {
        mem_allocator->free(hnode);
        return true;
    }
    return false;
}

void XHash::purge_free_list()
{
    HashNode* cur = fhead;
    while ( cur )
    {
        HashNode* next = cur->gnext;
        mem_allocator->free(cur);
        cur = next;
    }

    fhead = nullptr;
    num_free_nodes = 0;
}

void XHash::clear_hash()
{
    for (unsigned i = 0; i < nrows; i++)
        for (HashNode* node = table[i]; node;)
        {
            HashNode* xnode = node;
            node = node->next;
            release_node(xnode);
        }

    max_nodes = 0;
    num_nodes = 0;
    crow = 0;
    cursor = nullptr;
}

void* XHash::get_mru_user_data(uint8_t type)
{
    assert(type < num_lru_caches);
    return lru_caches[type]->get_mru_user_data();
}

void* XHash::get_lru_user_data(uint8_t type)
{
    assert(type < num_lru_caches);
    return lru_caches[type]->get_lru_user_data();
}

void* XHash::get_walk_user_data(uint8_t type)
{
    HashNode* walk_node = lru_caches[type]->get_walk_node();
    return walk_node ? walk_node->data : nullptr;
}

void* XHash::get_next_walk_user_data(uint8_t type)
{
    HashNode* walk_node = lru_caches[type]->get_next_walk_node();
    return walk_node ? walk_node->data : nullptr;
}

HashNode* XHash::release_lru_node(uint8_t type)
{
    assert(type < num_lru_caches);
    HashNode* hnode = lru_caches[type]->get_lru_node();
    while ( hnode )
    {
        if ( is_node_recovery_ok(hnode) )
        {
            lru_caches[type]->remove_node(hnode);
            free_user_data(hnode);
            unlink_node(hnode);
            --num_nodes;
            ++stats.memcap_prunes;
            break;
        }
        else
            hnode = lru_caches[type]->get_next_lru_node ();
    }
    return hnode;
}

void XHash::switch_node_lru_cache(HashNode* hnode, uint8_t old_type, uint8_t new_type)
{
    lru_caches[old_type]->remove_node(hnode);
    lru_caches[new_type]->insert(hnode);
}

bool XHash::switch_lru_cache(const void* key, uint8_t old_type, uint8_t new_type)
{
    assert(old_type < num_lru_caches);
    assert(new_type < num_lru_caches);

    int rindex = 0;
    HashNode* hnode = (HashNode*)find_node_row(key, rindex, old_type);
    if ( hnode )
    {
        switch_node_lru_cache(hnode, old_type, new_type);
        return true;
    }

    return false;
}

bool XHash::delete_lru_node(uint8_t type)
{
    assert(type < num_lru_caches);

    if ( HashNode* hnode = lru_caches[type]->remove_lru_node() )
    {
        unlink_node(hnode);
        free_user_data(hnode);
        mem_allocator->free(hnode);
        --num_nodes;
        return true;
    }

    return false;
}

bool XHash::delete_a_node()
{
    if ( delete_free_node() )
        return true;

    if ( delete_lru_node() )
        return true;

    return false;
}

int XHash::tune_memory_resources(unsigned work_limit, unsigned& num_freed)
{
    while ( work_limit-- and mem_allocator->is_over_capacity() )
    {
        if ( !delete_a_node() )
            break;

        ++stats.memcap_deletes;
        ++num_freed;
    }

    return ( mem_allocator->is_over_capacity() ) ? HASH_PENDING :  HASH_OK;
}

} // namespace snort
