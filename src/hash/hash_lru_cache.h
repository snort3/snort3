//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// hash_lru_cache.h author davis mcpherson davmcphe@cisco.com

#ifndef HASH_LRU_CACHE_H
#define HASH_LRU_CACHE_H

#include "hash_defs.h"

class HashLruCache
{
public:
    HashLruCache();

    void insert(snort::HashNode*);
    void touch(snort::HashNode*);
    void remove_node(snort::HashNode*);

    snort::HashNode* get_lru_node()
    {
        cursor = tail;
        return cursor;
    }

    snort::HashNode* get_next_lru_node()
    {
        if ( cursor )
            cursor = cursor->gprev;
        return cursor;
    }

    snort::HashNode* get_current_node()
    { return cursor; }

    void* get_mru_user_data()
    { return ( head ) ? head->data : nullptr; }

    void* get_lru_user_data()
    { return ( tail ) ? tail->data : nullptr; }

    snort::HashNode* remove_lru_node()
    {
        snort::HashNode* hnode = tail;
        if ( hnode )
            remove_node(hnode);

        return hnode;
    }

private:
    snort::HashNode* head = nullptr;
    snort::HashNode* tail = nullptr;
    snort::HashNode* cursor = nullptr;
};

#endif

