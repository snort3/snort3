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

// zhash is based on sfxhash - see xhash.cc for details

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "zhash.h"

#include <cassert>
#include <cstring>

#include "hash_defs.h"

using namespace snort;

//-------------------------------------------------------------------------
// private stuff
//-------------------------------------------------------------------------

static inline HashNode* s_node_alloc(int keysize)
{
    auto node = static_cast<HashNode*>(
        ::operator new(sizeof(HashNode) + keysize));

    *node = {};
    return node;
}

static inline void s_node_free(HashNode* node)
{ ::operator delete(node); }

void ZHash::delete_free_list()
{
    if ( !fhead )
        return;

    HashNode* cur = fhead;

    while ( cur )
    {
        fhead = cur->gnext;
        s_node_free(cur);
        cur = fhead;
    }
}

void ZHash::save_free_node(HashNode* node)
{
    if ( fhead )
    {
        node->gprev = nullptr;
        node->gnext = fhead;
        fhead->gprev = node;
        fhead = node;
    }
    else
    {
        node->gprev = nullptr;
        node->gnext = nullptr;
        fhead = node;
    }
}

HashNode* ZHash::get_free_node()
{
    HashNode* node = fhead;

    if ( fhead )
    {
        fhead = fhead->gnext;

        if ( fhead )
            fhead->gprev = nullptr;
    }

    return node;
}

void ZHash::glink_node(HashNode* node)
{
    if ( ghead )
    {
        node->gprev = nullptr;
        node->gnext = ghead;
        ghead->gprev = node;
        ghead = node;
    }
    else
    {
        node->gprev = nullptr;
        node->gnext = nullptr;
        ghead = node;
        gtail = node;
    }
}

void ZHash::gunlink_node(HashNode* node)
{
    if ( cursor == node )
        cursor = node->gprev;

    if ( ghead == node )
    {
        ghead = ghead->gnext;
        if ( ghead )
            ghead->gprev = nullptr;
    }

    if ( node->gprev )
        node->gprev->gnext = node->gnext;

    if ( node->gnext )
        node->gnext->gprev = node->gprev;

    if ( gtail == node )
        gtail = node->gprev;
}

void ZHash::link_node(HashNode* node)
{
    if ( table[node->rindex] )  // UNINITUSE
    {
        node->prev = nullptr;
        node->next = table[node->rindex];
        table[node->rindex]->prev = node;
        table[node->rindex] = node;
    }
    else
    {
        node->prev = nullptr;
        node->next = nullptr;
        table[node->rindex] = node;  // UNINITUSE
    }
}

void ZHash::unlink_node(HashNode* node)
{
    if ( node->prev )
    {
        node->prev->next = node->next;
        if ( node->next )
            node->next->prev = node->prev;
    }
    else if ( table[node->rindex] )
    {
        table[node->rindex] = table[node->rindex]->next;

        if ( table[node->rindex] )
            table[node->rindex]->prev = nullptr;
    }
}

void ZHash::move_to_front(HashNode* node)
{
    // move to front of row list
    if ( table[node->rindex] != node )
    {
        unlink_node(node);
        link_node(node);
    }

    // move to front of global list
    if ( node != ghead )
    {
        gunlink_node(node);
        glink_node(node);
    }
}

HashNode* ZHash::find_node_row(const void* key, int& row)
{
    unsigned hashkey = hashfcn->hash_fcn(
        hashfcn, (const unsigned char*)key, keysize);

    // Modulus is slow; use a table size that is a power of 2.
    int index = hashkey & (nrows - 1);
    row = index;

    for ( HashNode* node = table[index]; node; node = node->next )  // UNINITUSE
    {
        if ( hashfcn->keycmp_fcn(node->key, key, keysize) )
        {
            move_to_front(node);
            find_success++;
            return node;
        }
    }

    find_fail++;
    return nullptr;
}

//-------------------------------------------------------------------------
// public stuff
//-------------------------------------------------------------------------

ZHash::ZHash(int rows, int keysz)
    : keysize(keysz)
{
    // adjust rows to be power of 2
    if ( rows > 0 )
        nrows = hash_nearest_power_of_2(rows);
    else
        nrows = -rows;   // if negative use as is

    table = new HashNode*[nrows]();
    hashfcn = hashfcn_new(nrows);

    fhead = cursor = nullptr;
    ghead = gtail = nullptr;
    count = find_success = find_fail = 0;
}

ZHash::~ZHash()
{
    hashfcn_free(hashfcn);

    for ( unsigned i = 0; i < nrows; ++i )
    {
        for ( HashNode* node = table[i]; node; )
        {
            HashNode* onode = node;
            node = node->next;
            s_node_free(onode);
        }
    }

    delete[] table;
    delete_free_list();
}

void* ZHash::push(void* p)
{
    auto node = s_node_alloc(keysize);

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
    s_node_free(node);

    return pv;
}

void* ZHash::get(const void* key, bool *new_node)
{
    int row;
    HashNode* node = find_node_row(key, row);

    if ( node )
        return node->data;

    node = get_free_node();

    if ( !node )
        return nullptr;

    memcpy(node->key, key, keysize);

    node->rindex = row;
    link_node (node);
    glink_node(node);

    count++;

    if (new_node)
        *new_node = true;

    return node->data;
}

void* ZHash::find(const void* key)
{
    int row;
    HashNode* node = find_node_row(key, row);

    if ( node )
        return node->data;

    return nullptr;
}

void* ZHash::first()
{
    cursor = gtail;
    return cursor ? cursor->data : nullptr;
}

void* ZHash::next()
{
    if ( !cursor )
        return nullptr;

    cursor = cursor->gprev;
    return cursor ? cursor->data : nullptr;
}

void* ZHash::current()
{
    return cursor ? cursor->data : nullptr;
}

bool ZHash::touch()
{
    HashNode* node = cursor;

    if ( !node )
        return false;

    cursor = cursor->gprev;

    if ( node != ghead )
    {
        gunlink_node(node);
        glink_node(node);
        return true;
    }
    return false;
}

bool ZHash::move_to_free_list(HashNode* node)
{
    if ( !node )
        return false;

    unlink_node(node);
    gunlink_node(node);
    count--;
    save_free_node(node);

    return true;
}

bool ZHash::release()
{
    HashNode* node = cursor;
    cursor = nullptr;
    return move_to_free_list(node);
}

bool ZHash::release(const void* key)
{
    int row;
    HashNode* node = find_node_row(key, row);
    return move_to_free_list(node);
}

void* ZHash::remove(const void* key)
{
    void* pv = nullptr;
    int row;
    HashNode* node = find_node_row(key, row);
    if ( node )
    {
        unlink_node(node);
        gunlink_node(node);
        count--;
        pv = node->data;
        s_node_free(node);
    }

    return pv;
}

void ZHash::set_key_opcodes(hash_func hash_fcn, keycmp_func keycmp_fcn)
{
    hashfcn_set_keyops(hashfcn, hash_fcn, keycmp_fcn);
}
