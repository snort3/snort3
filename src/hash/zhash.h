//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

struct HashFnc;
struct ZHashNode;

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

    bool remove(const void* key);
    bool remove();

    inline unsigned get_count() { return count; }

    int set_keyops(
        unsigned (* hash_fcn)(HashFnc* p, const unsigned char* d, int n),
        int (* keycmp_fcn)(const void* s1, const void* s2, size_t n));

private:
    ZHashNode* get_free_node();
    ZHashNode* find_node_row(const void*, int&);

    void glink_node(ZHashNode*);
    void gunlink_node(ZHashNode*);

    void link_node(ZHashNode*);
    void unlink_node(ZHashNode*);

    void delete_free_list();
    void save_free_node(ZHashNode*);

    bool remove(ZHashNode*);
    void move_to_front(ZHashNode*);
    int nearest_powerof2(int nrows);

private:
    HashFnc* hashfcn;
    int keysize;

    unsigned nrows;
    unsigned count;

    unsigned find_fail;
    unsigned find_success;

    ZHashNode** table;
    ZHashNode* ghead, * gtail;
    ZHashNode* fhead;
    ZHashNode* cursor;
};

#endif

