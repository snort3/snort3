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
// http2_hpack_dynamic_table.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_hpack_dynamic_table.h"

#include <string.h>

#include "http2_hpack_table.h"

HpackDynamicTable::~HpackDynamicTable()
{
    assert(num_entries <= array_capacity);
    const uint32_t end_index = (start + num_entries) % array_capacity;
    for (uint32_t i = 0; i < array_capacity; i++)
    {
        if ((start <= end_index and (i >= start and i < end_index)) or
            (start > end_index and (i >= start or i < end_index)))
        {
            delete circular_array[i];
            circular_array[i] = nullptr;
        }
    }
    delete[] circular_array;
}

void HpackDynamicTable::add_entry(Field name, Field value)
{
    const uint32_t new_entry_size = name.length() + value.length() + RFC_ENTRY_OVERHEAD;

    // As per the RFC, attempting to add an entry that is larger than the max size of the table is
    // not an error, it causes the table to be cleared
    if (new_entry_size > max_size)
    {
        prune_to_size(0);
        return;
    }

    // If add entry would exceed max table size, evict old entries
    prune_to_size(max_size - new_entry_size);

    // Add new entry to the front of the table (newest entry = lowest index)
    HpackTableEntry *new_entry = new HpackTableEntry(name, value);

    start = (start + array_capacity - 1) % array_capacity;

    // FIXIT-P May want to initially allocate small circular array and expand as needed. For now
    // array big enough to support hardcoded max table size of 4096 bytes
    assert(num_entries < array_capacity);
    circular_array[start] = new_entry;

    num_entries++;
    rfc_table_size += new_entry_size;
}

const HpackTableEntry* HpackDynamicTable::get_entry(uint32_t virtual_index) const
{
    const uint32_t dyn_index = virtual_index - HpackIndexTable::STATIC_MAX_INDEX - 1;

    if (num_entries == 0 or dyn_index > num_entries - 1)
        return nullptr;

    const uint32_t arr_index = (start + dyn_index) % array_capacity;
    return circular_array[arr_index];
}

/* This is called when adding a new entry and when receiving a dynamic table size update.
 * If adding the new entry would make the table size exceed the max size, entries are pruned
 * until the new entry fits. If the dynamic size update is smaller than the current table size,
 * entries are pruned until the table is no larger than the max size. Entries are pruned least
 * recently added first.
 * Note: dynamic size updates not yet implemented
 */
void HpackDynamicTable::prune_to_size(uint32_t new_max_size)
{
    while (rfc_table_size > new_max_size)
    {
        const uint32_t last_index = (start + num_entries - 1 + array_capacity) % array_capacity;
        HpackTableEntry *last_entry = circular_array[last_index];
        num_entries--;
        rfc_table_size -= last_entry->name.length() + last_entry->value.length() +
            RFC_ENTRY_OVERHEAD;
        delete last_entry;
        circular_array[last_index] = nullptr;
    }
}
