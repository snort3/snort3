//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
// hash_defs.h author davis mcpherson davmcphe@cisco.com>

#ifndef HASH_DEFS_H
#define HASH_DEFS_H

#include "hash_key_operations.h"
#include "main/snort_types.h"

namespace snort
{
#define HASH_NOMEM     (-2)
#define HASH_NOT_FOUND (-1)
#define HASH_OK        0
#define HASH_INTABLE   1
#define HASH_PENDING   2

class HashNode
{
public:
    HashNode* gnext; // lru or free node list
    HashNode* gprev;
    HashNode* next;  // hash row node list
    HashNode* prev;
    void* key;
    void* data;
    int rindex;
};
}
#endif
