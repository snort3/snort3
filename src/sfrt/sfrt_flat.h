//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "utils/segment_mem.h"

typedef MEM_OFFSET INFO; /* To be replaced with a pointer to a policy */
typedef MEM_OFFSET FLAT_INDEX;
typedef MEM_OFFSET TABLE_PTR;

typedef enum
{
    SAVE_TO_NEW,
    SAVE_TO_CURRENT
}SaveDest;

typedef int64_t (* updateEntryInfoFunc)(INFO* entryInfo, INFO newInfo,
    SaveDest saveDest, uint8_t* base);
typedef struct
{
    FLAT_INDEX index;
    int length;
} tuple_flat_t;

// FIXIT-L circular include here
#include "sfrt/sfrt_flat_dir.h"

/******************************************************************
   Master table struct.  Abstracts DIR and LC-trie methods         */
typedef struct
{
    uint32_t num_ent; /* Number of entries in the policy table */
    uint32_t max_size; /* Max size of policies array */
    char ip_type; /* Only IPs of this family will be used */
    char table_flat_type;
    char mem_type;
    uint32_t allocated;
    INFO data; /* data table. Each IP points to an entry here */
    TABLE_PTR rt; /* Actual "routing" table */
    TABLE_PTR rt6; /* Actual "routing" table */
    TABLE_PTR list_info; /* List file information table (entry information)*/
} table_flat_t;
/*******************************************************************/

/* Abstracted routing table API */
table_flat_t* sfrt_flat_new(char table_flat_type, char ip_type,
    long data_size, uint32_t mem_cap);
void sfrt_flat_free(TABLE_PTR table);

GENERIC sfrt_flat_lookup(const snort::SfIp* ip, table_flat_t* table);
GENERIC sfrt_flat_dir8x_lookup(const snort::SfIp* ip, table_flat_t* table);

int sfrt_flat_insert(snort::SfCidr* cidr, unsigned char len, INFO ptr, int behavior,
    table_flat_t* table, updateEntryInfoFunc updateEntry);
uint32_t sfrt_flat_usage(table_flat_t* table);
uint32_t sfrt_flat_num_entries(table_flat_t* table);

#endif

