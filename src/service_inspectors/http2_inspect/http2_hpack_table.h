//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// http2_hpack_table.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_HPACK_TABLE_H
#define HTTP2_HPACK_TABLE_H

#include "main/snort_types.h"

#include "http2_enum.h"

#define STATIC_MAX_INDEX 61
#define PSEUDO_HEADER_MAX_INDEX 14

// Only static table is implemented. lookup() will be extended to support dynamic table
// lookups once dynamic table is implemented
class Http2HpackTable
{
public:
    struct TableEntry
    {
        const char* name;
        const char* value;
    };

    const static TableEntry* lookup(uint64_t index);

private:
    const static TableEntry table[STATIC_MAX_INDEX + 1];
};
#endif
