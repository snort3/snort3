//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"
#include "utils/sfmemcap.h"

#include "hashfcn.h"

namespace snort
{
#define HASH_NOMEM    (-2)
#define HASH_ERR      (-1)
#define HASH_OK        0
#define HASH_INTABLE   1
#define HASH_PENDING   2

struct HashNode
{
    struct HashNode* gnext; // global node list - used for aging nodes
    struct HashNode* gprev;
    struct HashNode* next;  // row node list
    struct HashNode* prev;
    int rindex;     // row index of table this node belongs to.
    void* key;      // Pointer to the key.
    void* data;     // Pointer to the users data, this is not copied !
};

typedef int (* Hash_FREE_FCN)(void* key, void* data);
}
#endif
