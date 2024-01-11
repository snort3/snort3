//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "hash/xhash.h"

class ZHash : public snort::XHash
{
public:
    ZHash(int nrows, int keysize, uint8_t lru_count = 1, bool recycle = true);

    ZHash(const ZHash&) = delete;
    ZHash& operator=(const ZHash&) = delete;

    void* push(void* p);
    void* pop();

    void* get(const void* key, uint8_t type = 0);
    void* remove(uint8_t type = 0);

    void* lru_first(uint8_t type = 0);
    void* lru_next(uint8_t type = 0);
    void* lru_current(uint8_t type = 0);
    void lru_touch(uint8_t type = 0);
};

#endif

