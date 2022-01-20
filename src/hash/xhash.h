//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/counts.h"
#include "main/snort_types.h"
#include "utils/memcap_allocator.h"

class HashLruCache;

namespace snort
{
class HashKeyOperations;
class HashNode;

struct XHashStats
{
    PegCount nodes_created = 0;
    PegCount memcap_prunes = 0;
    PegCount memcap_deletes = 0;
    PegCount release_recycles = 0;
    PegCount release_deletes = 0;
};

class SO_PUBLIC XHash
{
public:
    XHash(int rows, int keysize);
    XHash(int rows, int keysize, int datasize, unsigned long memcap);
    virtual ~XHash();

    int insert(const void* key, void* data);
    HashNode* find_node(const void* key);
    HashNode* find_first_node();
    HashNode* find_next_node();
    void* get_user_data();
    void* get_user_data(const void* key);
    void release();
    int release_node(const void* key);
    int release_node(HashNode* node);
    void* get_mru_user_data();
    void* get_lru_user_data();
    bool delete_lru_node();
    void clear_hash();
    bool full() const { return !fhead; }

    // set max hash nodes, 0 == no limit
    void set_max_nodes(int max)
    { max_nodes = max; }

    unsigned get_num_nodes()
    { return num_nodes; }

    void set_memcap(unsigned long memcap)
    { mem_allocator->set_mem_capacity(memcap); }

    unsigned long get_memcap()
    { return mem_allocator->get_mem_capacity(); }

    unsigned long get_mem_used()
    { return mem_allocator->get_mem_allocated(); }

    const XHashStats& get_stats() const
    { return stats; }

    virtual int tune_memory_resources(unsigned work_limit, unsigned& num_freed);

protected:
    void initialize(HashKeyOperations*);
    void initialize();

    void initialize_node (HashNode*, const void* key, void* data, int index);
    HashNode* allocate_node(const void* key, void* data, int index);
    HashNode* find_node_row(const void* key, int& rindex);
    void link_node(HashNode*);
    void unlink_node(HashNode*);
    bool delete_a_node();
    void save_free_node(HashNode*);
    HashNode* get_free_node();
    void delete_hash_table();

    virtual bool is_node_recovery_ok(HashNode*)
    { return true; }

    virtual void free_user_data(HashNode*)
    { }

    MemCapAllocator* mem_allocator = nullptr;
    HashLruCache* lru_cache = nullptr;
    unsigned nrows = 0;
    unsigned keysize = 0;
    unsigned num_nodes = 0;
    bool recycle_nodes = true;
    bool anr_enabled = true;

private:
    HashNode** table = nullptr;
    HashKeyOperations* hashkey_ops = nullptr;
    HashNode* cursor = nullptr;
    HashNode* fhead = nullptr;
    unsigned datasize = 0;
    unsigned long mem_cap = 0;
    unsigned max_nodes = 0;
    unsigned crow = 0;
    XHashStats stats;

    void set_number_of_rows(int nrows);
    void move_to_front(HashNode*);
    bool delete_free_node();
    HashNode* release_lru_node();
    void update_cursor();
    void purge_free_list();
};

} // namespace snort
#endif

