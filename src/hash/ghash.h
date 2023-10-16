//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <cstring>
#include "hash_key_operations.h"
#include "main/snort_types.h"

namespace snort
{
struct GHashNode
{
    struct GHashNode* next;
    struct GHashNode* prev;
    const void* key;
    void* data;
};

typedef void (* gHashFree)(void*);

class SO_PUBLIC GHash
{
public:
    GHash(int nrows, unsigned keysize, bool userkey, gHashFree);
    ~GHash();

    int insert(const void* const key, void* const data);
    int remove(const void* const key);
    void* find(const void* const key);
    GHashNode* find_first();
    GHashNode* find_next();
    void set_hashkey_ops(HashKeyOperations*);

    unsigned get_count() const
    { return count; }

private:
    GHashNode* find_node(const void* const key, unsigned index);
    int free_node(unsigned index, GHashNode*);
    void next();

    unsigned get_key_length(const void* const key)
    { return ( keysize > 0  ) ? keysize : strlen((const char*)key) + 1; }

    unsigned get_index(const void* const key)
    {
        unsigned hashkey = hashfcn->do_hash((const unsigned char*)key, get_key_length(key));
        return hashkey % nrows;
    }

    unsigned keysize;     // bytes in key, if < 0 -> keys are strings
    bool userkey;          // user owns the key */
    gHashFree userfree;
    int nrows;            // # rows int the hash table use a prime number 211, 9871
    HashKeyOperations* hashfcn;
    GHashNode** table;    // array of node ptr's
    unsigned count;       // total # nodes in table
    int crow;             // findfirst/next row in table
    GHashNode* cnode;     // findfirst/next node ptr

};


}
#endif

