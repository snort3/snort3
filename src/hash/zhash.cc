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

// zhash is based on sfxhash - see xhash.cc for details

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "zhash.h"

#include <cassert>
#include <cstring>

#include "flow/flow_key.h"

#include "hash_defs.h"
#include "hash_key_operations.h"
#include "hash_lru_cache.h"

using namespace snort;

//-------------------------------------------------------------------------
// public stuff
//-------------------------------------------------------------------------


ZHash::ZHash(int rows, int key_len, uint8_t lru_count, bool recycle)
    : XHash(rows, key_len, lru_count)
{
    initialize(new FlowHashKeyOps(nrows));
    anr_enabled = false;
    recycle_nodes = recycle;
}

void* ZHash::get(const void* key, uint8_t type)
{
    assert(key);
    assert(type < num_lru_caches);
    
    int index;
    HashNode* node = find_node_row(key, index);
    if ( node )
        return node->data;

    node = get_free_node();
    if ( !node )
        return nullptr;

    memcpy(node->key, key, keysize);
    node->rindex = index;
    link_node(node);
    lru_caches[type]->insert(node);
    num_nodes++;
    return node->data;
}

void* ZHash::remove(uint8_t type)
{
    assert(type < num_lru_caches);
    HashNode* node = lru_caches[type]->get_current_node();
    assert(node);
    void* pv = node->data;

    unlink_node(node);
    lru_caches[type]->remove_node(node);
    num_nodes--;
    mem_allocator->free(node);
    return pv;
}

void* ZHash::push(void* p)
{
    auto node = (HashNode*)mem_allocator->allocate();
    node->key = (char*)node + sizeof(HashNode);
    node->data = p;
    save_free_node(node);
    return node->key;
}

void* ZHash::pop()
{
    HashNode* node = get_free_node();
    if ( !node )
        return nullptr;

    void* pv = node->data;
    mem_allocator->free(node);

    return pv;
}

void* ZHash::lru_first(uint8_t type)
{
    assert(type < num_lru_caches);
    HashNode* node = lru_caches[type]->get_lru_node();
    return node ? node->data : nullptr;
}

void* ZHash::lru_next(uint8_t type)
{
    assert(type < num_lru_caches);
    HashNode* node = lru_caches[type]->get_next_lru_node();
    return node ? node->data : nullptr;
}

void* ZHash::lru_current(uint8_t type)
{
    assert(type < num_lru_caches);
    HashNode* node = lru_caches[type]->get_current_node();
    return node ? node->data : nullptr;
}

void ZHash::lru_touch(uint8_t type)
{
    assert(type < num_lru_caches);
    HashNode* node = lru_caches[type]->get_current_node();
    assert(node);
    lru_caches[type]->touch(node);
}

uint64_t ZHash::get_node_count(uint8_t type)
{
    assert(type < num_lru_caches);
    return lru_caches[type]->get_node_count();
}
