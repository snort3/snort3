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

#ifndef ZHASH_H
#define ZHASH_H

#include <cstddef>

#include "hashfcn.h"

namespace snort
{
struct HashNode;
}

class ZHash
{
public:
    ZHash(int nrows, int keysize);
    ~ZHash();

    ZHash(const ZHash&) = delete;
    ZHash& operator=(const ZHash&) = delete;

    void* push(void* p);
    void* pop();

    void* first();
    void* next();
    void* current();
    bool touch();

    void* find(const void* key);
    void* get(const void* key, bool *new_node = nullptr);
    bool release(const void* key);
    bool release();
    void* remove(const void* key);
    void set_key_opcodes(hash_func, keycmp_func);

    inline unsigned get_count()
    { return count; }

private:
    snort::HashNode* get_free_node();
    snort::HashNode* find_node_row(const void*, int&);

    void glink_node(snort::HashNode*);
    void gunlink_node(snort::HashNode*);

    void link_node(snort::HashNode*);
    void unlink_node(snort::HashNode*);

    void delete_free_list();
    void save_free_node(snort::HashNode*);

    bool move_to_free_list(snort::HashNode*);
    void move_to_front(snort::HashNode*);

private:
    HashFnc* hashfcn;
    int keysize;
    unsigned nrows;
    unsigned count;

    unsigned find_fail;
    unsigned find_success;

    snort::HashNode** table;
    snort::HashNode* ghead;
    snort::HashNode* gtail;
    snort::HashNode* fhead;
    snort::HashNode* cursor;
};

#endif

