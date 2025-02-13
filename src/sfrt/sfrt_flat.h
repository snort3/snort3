//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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
/*
** 9/7/2011 - Initial implementation ... Hui Cao <hcao@sourcefire.com>
**
*/

#ifndef SFRT_FLAT_H
#define SFRT_FLAT_H

// This is based on the original sfrt.h, but using the flat segment memory.
// When allocating memory, it uses memory in the segment, and returns the offset.
// When accessing memory, it must use the base address and offset to
// correctly refer to it.

#include "sfrt/sfrt.h"
#include "sfrt/sfrt_flat_dir.h"

typedef MEM_OFFSET INFO; /* To be replaced with a pointer to a policy */
typedef MEM_OFFSET FLAT_INDEX;
typedef MEM_OFFSET TABLE_PTR;

enum SaveDest
{
    SAVE_TO_NEW,
    SAVE_TO_CURRENT
};

typedef int64_t (*updateEntryInfoFunc)(INFO* entryInfo, INFO newInfo,
    SaveDest saveDest, uint8_t* base, void* data);

struct tuple_flat_t
{
    FLAT_INDEX index;
    int length;
};

// Master table struct.  Abstracts DIR and LC-trie methods
struct table_flat_t
{
    unsigned num_ent = 0;   // Number of entries in the policy table
    unsigned max_size = 0;  // Max size of policies array
    char ip_type;           // Only IPs of this family will be used
    char table_flat_type;
    char mem_type;
    unsigned allocated;
    INFO data;              // data table. Each IP points to an entry here
    TABLE_PTR rt;           // Actual "routing" table
    TABLE_PTR rt6;          // Actual "routing" table
    TABLE_PTR list_info;    // List file information table (entry information)
};
/*******************************************************************/

GENERIC sfrt_flat_dir8x_lookup(const snort::SfIp* ip, table_flat_t* table);

struct IPLOOKUP;
struct RtTable
{
    void sfrt_flat_new(char table_flat_type, char ip_type, long data_size, uint32_t mem_cap);
    GENERIC sfrt_flat_lookup(const snort::SfIp*);

    return_codes sfrt_flat_insert(snort::SfCidr* cidr, unsigned char len, INFO ptr, int behavior,
        updateEntryInfoFunc, void* update_entry_info_data);
    unsigned sfrt_flat_usage() const;
    unsigned sfrt_flat_num_entries() const;
    table_flat_t* get_table() const
    { return table; }

    void segment_meminit(uint8_t* buff, size_t mem_cap)
    {
        base_ptr = buff;
        unused_ptr = 0;
        unused_mem = mem_cap;
    }
    MEM_OFFSET segment_snort_calloc(size_t num, size_t size);

protected:
    TABLE_PTR sfrt_dir_flat_new(uint32_t mem_cap, int count, ...);
    tuple_flat_t sfrt_dir_flat_lookup(const uint32_t* addr, int numAddrDwords, TABLE_PTR table_ptr);
    return_codes sfrt_dir_flat_insert(const uint32_t* addr, int numAddrDwords, int len, word data_index,
        int behavior, TABLE_PTR, updateEntryInfoFunc updateEntry, void* update_entry_info_data, INFO *data);
    uint32_t sfrt_dir_flat_usage(TABLE_PTR) const;
    TABLE_PTR _sub_table_flat_new(dir_table_flat_t* root, uint32_t dimension, uint32_t prefill, uint32_t bit_length);
    return_codes _dir_sub_insert(IPLOOKUP* ip, int length, int cur_len, INFO ptr,
        int current_depth, int behavior, SUB_TABLE_PTR sub_ptr, dir_table_flat_t* root_table,
        updateEntryInfoFunc updateEntry, void* update_entry_info_data, INFO* data);
    int64_t _dir_update_info(int index, int fill, word length, uint32_t val, SUB_TABLE_PTR sub_ptr,
        updateEntryInfoFunc updateEntry, void* update_entry_info_data, INFO* data);
    tuple_flat_t _dir_sub_flat_lookup(IPLOOKUP* ip, TABLE_PTR table_ptr);

    MEM_OFFSET segment_snort_alloc(size_t size);
    void segment_free(MEM_OFFSET)
    { }
    size_t segment_unusedmem() const
    { return unused_mem; }
    void* segment_basePtr() const
    { return base_ptr; }

    table_flat_t* table = nullptr;
    MEM_OFFSET unused_ptr = 0;
    size_t unused_mem = 0;
    void* base_ptr = nullptr;
};

#endif

