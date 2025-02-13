//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// hash_lru_cache.cc author davis mcpherson davmcphe@cisco.com

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash_lru_cache.h"

#include <cassert>
#include "utils/util.h"

using namespace snort;

HashLruCache::HashLruCache()
{
    head = nullptr;
    tail = nullptr;
}

void HashLruCache::insert(HashNode* hnode)
{
    hnode->gprev = nullptr;
    hnode->gnext = head;
    if (head)
        head->gprev = hnode;
    else
        tail = hnode;
    head = hnode;
    node_count++;
}

void HashLruCache::touch(HashNode* hnode)
{
    if ( hnode == cursor )
        cursor = hnode->gprev;

    if ( walk_cursor == hnode )
        walk_cursor = hnode->gprev;

    if ( hnode != head )
    {
        remove_node(hnode);
        insert(hnode);
    }
}

void HashLruCache::remove_node(HashNode* hnode)
{
    if ( cursor == hnode )
        cursor = hnode->gprev;

    if ( walk_cursor == hnode )
        walk_cursor = hnode->gprev;

    if ( head == hnode )
    {
        head = head->gnext;
        if ( head )
            head->gprev = nullptr;
    }

    if ( hnode->gprev )
        hnode->gprev->gnext = hnode->gnext;
    if ( hnode->gnext )
        hnode->gnext->gprev = hnode->gprev;

    if ( tail == hnode )
        tail = hnode->gprev;
    node_count--;
}
