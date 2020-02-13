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

// xhash.h author Marc Norton

#ifndef XHASH_H
#define XHASH_H

// generic hash table - stores and maps key + data pairs
// (supports memcap and automatic memory recovery when out of memory)

#include "utils/sfmemcap.h"
#include "main/snort_types.h"

#include "hash_defs.h"
#include "hashfcn.h"

namespace snort
{
class SO_PUBLIC XHash
{
public:
    XHash(int nrows_, int keysize_, int datasize_, unsigned long memcap,
        bool anr_enabled, Hash_FREE_FCN, Hash_FREE_FCN, bool recycle_nodes);
    ~XHash();

    int free_over_allocations(unsigned work_limit, unsigned* num_freed);
    void clear();

    int insert(const void* key, void* data);
    HashNode* get_node(const void* key);
    HashNode* get_node_with_prune(const void* key, bool* prune_performed);
    int release_node(void* key);
    int release_node(HashNode* node);
    int delete_anr_or_lru_node();
    HashNode* find_node(const void* key);
    HashNode* find_first_node();
    HashNode* find_next_node();
    void* get_user_data(void* key);
    void* get_mru_user_data();
    void* get_lru_user_data();
    void set_key_opcodes(hash_func, keycmp_func);

    // Set the maximum nodes used in this hash table.
    //  Specifying 0 is unlimited (or otherwise limited by memcap).
    void set_max_nodes(int max)
    { max_nodes = max; }

    unsigned get_node_count()
    { return count; }

    unsigned get_anr_count()
    { return anr_count; }

    unsigned get_total_finds()
    { return find_success + find_fail; }

    unsigned get_find_fails()
    { return find_fail; }

    unsigned get_find_successes()
    { return find_success; }

    void set_memcap(unsigned long new_memcap)
    { mc.memcap = new_memcap; }

    unsigned long get_memcap()
    { return mc.memcap; }

    unsigned long get_mem_used()
    { return mc.memused; }

    const HashNode* get_cnode () const
    { return cnode; }

    int get_keysize () const
    { return keysize; }

private:
    void purge_free_list();
    void save_free_node(HashNode* hnode);
    HashNode* get_free_node();
    void glink_node(HashNode* hnode);
    void gunlink_node(HashNode* hnode);
    void gmove_to_front(HashNode* hnode);
    HashNode* gfind_first();
    HashNode* gfind_next();
    void link_node(HashNode* hnode);
    void unlink_node(HashNode* hnode);
    void move_to_front(HashNode* n);
    HashNode* allocate_node();
    HashNode* find_node_row(const void* key, int* rindex);
    void update_cnode();
    int delete_free_node();

    HashFnc* hashfcn = nullptr;     // hash function
    int keysize = 0;                // bytes in key, if <= 0 -> keys are strings - FIXIT-H does negative keysize work?
    int datasize = 0;               // bytes in key, if == 0 -> user data
    unsigned mem_allocated_per_entry = 0;
    HashNode** table = nullptr;  	// array of node ptr's */
    unsigned nrows = 0;             // # rows int the hash table use a prime number 211, 9871
    unsigned count = 0;             // total # nodes in table
    unsigned crow = 0;              // findfirst/next row in table
    HashNode* cnode = nullptr;     // find_[first|next] node ptr
    int splay = 1;                  // whether to splay nodes with same hash bucket
    unsigned max_nodes = 0;         // maximum # of nodes within a hash
    MEMCAP mc;
    unsigned find_fail = 0;
    unsigned find_success = 0;

    HashNode* ghead = nullptr;     // global - root of all nodes allocated in table
    HashNode* gtail = nullptr;
    HashNode* gnode = nullptr;     // gfirst/gnext node ptr */
    HashNode* fhead = nullptr;     // list of free nodes, which are recycled
    HashNode* ftail = nullptr;
    bool recycle_nodes = false;     // recycle nodes...

    // Automatic Node Recover (ANR): When number of nodes in hash is equal
    // to max_nodes, remove the least recently used nodes and use it for
    // the new node. anr_tries indicates # of ANR tries.*/
    unsigned anr_tries = 0;
    unsigned anr_count = 0;      // # ANR ops performed
    bool anr_enabled = false;    // false = anr disable, true = anr enabled

    Hash_FREE_FCN anr_free = nullptr;
    Hash_FREE_FCN usr_free = nullptr;
};

} // namespace snort
#endif

