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
// http2_hpack_dynamic_table.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_HPACK_DYNAMIC_TABLE_H
#define HTTP2_HPACK_DYNAMIC_TABLE_H

#include "service_inspectors/http_inspect/http_field.h"
#include "main/snort_types.h"

#include "http2_enum.h"

struct HpackTableEntry;

class HpackDynamicTable
{
public:
    // FIXIT-M allocate array based on actual max_size from settings
    HpackDynamicTable() : circular_array(new HpackTableEntry*[DEFAULT_NUM_ENTRIES]()) { }
    ~HpackDynamicTable();
    const HpackTableEntry* get_entry(uint32_t index) const;
    void add_entry(Field name, Field value);
    void prune_to_size(uint32_t new_max_size);
    // FIXIT-M implement handle_dynamic_size_update function
private:
    const static uint32_t RFC_ENTRY_OVERHEAD = 32;

    // FIXIT-H set/update these parameters dynamically. For now hardcoded
    const static uint32_t DEFAULT_MAX_SIZE = 4096;
    const static uint32_t DEFAULT_NUM_ENTRIES = DEFAULT_MAX_SIZE / RFC_ENTRY_OVERHEAD;
    uint32_t array_capacity = DEFAULT_NUM_ENTRIES;
    uint32_t max_size = DEFAULT_MAX_SIZE;

    uint32_t start = 0;
    uint32_t num_entries = 0;
    uint32_t rfc_table_size = 0;
    HpackTableEntry** circular_array;
};
#endif
