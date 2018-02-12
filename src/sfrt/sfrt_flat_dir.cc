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
// 9/7/2011 - Initial implementation ... Hui Cao <hcao@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfrt_flat.h" // FIXIT-L these includes are circular
#include "sfrt_flat_dir.h"

#include <cstdarg>

#if SIZEOF_UNSIGNED_LONG_INT == 8
#define ARCH_WIDTH 64
#else
#define ARCH_WIDTH 32
#endif

typedef struct
{
    const uint32_t* addr;
    int bits;
} IPLOOKUP;

/* Create new "sub" table of 2^width entries */
static TABLE_PTR _sub_table_flat_new(dir_table_flat_t* root, uint32_t dimension,
    uint32_t prefill, uint32_t bit_length)
{
    int width = root->dimensions[dimension];
    int len = 1 << width;
    int index;
    dir_sub_table_flat_t* sub;
    TABLE_PTR sub_ptr;
    uint8_t* base;
    DIR_Entry* entries;

    /* Check if creating this node will exceed the memory cap.
     * The symbols in the conditional (other than cap), come from the
     * allocs below. */
    if ( root->mem_cap < ( root->allocated +
        sizeof(dir_sub_table_flat_t) +
        sizeof(DIR_Entry) * len ) ||
        bit_length > 128)
    {
        return 0;
    }

    /* Set up the initial prefilled "sub table" */
    sub_ptr = segment_snort_alloc(sizeof(dir_sub_table_flat_t));

    if (!sub_ptr)
    {
        return 0;
    }

    base = (uint8_t*)segment_basePtr();
    sub = (dir_sub_table_flat_t*)(&base[sub_ptr]);

    /* This keeps the width readily available rather than recalculating it
     * from the number of entries during an insert or lookup */
    sub->width = width;

    /* need 2^sub->width entries */
    /* A "length" needs to be stored with each entry above.  The length refers
     * to how specific the insertion that set the entry was.  It is necessary
     * so that the entry is not overwritten by less general routing
     * information if "RT_FAVOR_SPECIFIC" insertions are being performed. */
    sub->num_entries = len;

    sub->entries = segment_snort_alloc(sizeof(DIR_Entry) * sub->num_entries);

    if (!sub->entries)
    {
        segment_free(sub_ptr);
        return 0;
    }

    entries = (DIR_Entry*)(&base[sub->entries]);
    /* Can't use memset here since prefill is multibyte */
    for (index = 0; index < sub->num_entries; index++)
    {
        entries[index].value = prefill;
        entries[index].length = (uint8_t)bit_length;
    }

    sub->cur_num = 0;

    root->allocated += sizeof(dir_sub_table_flat_t) + sizeof(DIR_Entry) * sub->num_entries;

    root->cur_num++;

    return sub_ptr;
}

/* Create new dir-n-m root table with 'count' depth */
TABLE_PTR sfrt_dir_flat_new(uint32_t mem_cap, int count,...)
{
    va_list ap;
    int index;
    TABLE_PTR table_ptr;
    dir_table_flat_t* table;
    uint8_t* base;

    table_ptr = segment_snort_alloc(sizeof(dir_table_flat_t));

    if (!table_ptr)
    {
        return 0;
    }

    base = (uint8_t*)segment_basePtr();
    table = (dir_table_flat_t*)(&base[table_ptr]);

    table->allocated = 0;

    table->dim_size = count;

    va_start(ap, count);

    for (index=0; index < count; index++)
    {
        uint32_t val = va_arg(ap, int);
        table->dimensions[index] = val;
    }

    va_end(ap);

    table->mem_cap = mem_cap;

    table->cur_num = 0;

    table->sub_table = _sub_table_flat_new(table, 0, 0, 0);

    if (!table->sub_table)
    {
        segment_free(table_ptr);
        return 0;
    }

    table->allocated += sizeof(dir_table_flat_t) + sizeof(int)*count;

    return table_ptr;
}

/* Traverse "sub" tables, freeing each */
static void _sub_table_flat_free(uint32_t* allocated, SUB_TABLE_PTR sub_ptr)
{
    int index;
    dir_sub_table_flat_t* sub;
    uint8_t* base;

    base = (uint8_t*)segment_basePtr();
    sub = (dir_sub_table_flat_t*)(&base[sub_ptr]);

    sub->cur_num--;

    for (index=0; index < sub->num_entries; index++)
    {
        /* The following condition will only be true if
         * this entry is a pointer  */
        DIR_Entry* entry = (DIR_Entry*)(&base[sub->entries]);
        if ( !entry[index].length && entry[index].value )
        {
            _sub_table_flat_free(allocated, entry[index].value);
        }
    }

    if (sub->entries)
    {
        /* This probably does not need to be checked
         * since if it was not allocated, we would have errored out
         * in _sub_table_flat_new */
        segment_free(sub->entries);

        *allocated -= sizeof(DIR_Entry) * sub->num_entries;
    }

    segment_free(sub_ptr);

    *allocated -= sizeof(dir_sub_table_flat_t);
}

/* Free the DIR-n-m structure */
void sfrt_dir_flat_free(TABLE_PTR tbl_ptr)
{
    dir_table_flat_t* table;
    uint8_t* base;

    if (!tbl_ptr)
    {
        return;
    }

    base = (uint8_t*)segment_basePtr();
    table = (dir_table_flat_t*)(&base[tbl_ptr]);

    if (table->sub_table)
    {
        _sub_table_flat_free(&table->allocated, table->sub_table);
    }

    segment_free(tbl_ptr);
}

static inline void _dir_fill_all(uint32_t* allocated, uint32_t index, uint32_t fill,
    word length, uint32_t val, SUB_TABLE_PTR sub_ptr)
{
    dir_sub_table_flat_t* subtable;
    uint8_t* base;

    base = (uint8_t*)segment_basePtr();
    subtable = (dir_sub_table_flat_t*)(&base[sub_ptr]);

    /* Fill entries */
    for (; index < fill; index++)
    {
        /* Before overwriting this entry, verify there's not an existing
         * pointer ... otherwise free it to avoid a huge memory leak. */
        DIR_Entry* entry = (DIR_Entry*)(&base[subtable->entries]);
        if ( entry[index].value && !entry[index].length)
        {
            _sub_table_flat_free(allocated, entry[index].value);
        }

        entry[index].value = val;
        entry[index].length = (uint8_t)length;
    }
}

static inline void _dir_fill_less_specific(int index, int fill,
    word length, uint32_t val, SUB_TABLE_PTR sub_ptr)
{
    dir_sub_table_flat_t* subtable;
    uint8_t* base;

    base = (uint8_t*)segment_basePtr();
    subtable = (dir_sub_table_flat_t*)(&base[sub_ptr]);

    /* Fill entries */
    for (; index < fill; index++)
    {
        /* If we encounter a pointer, and we're inserting at this level, we
         * automatically know that this entry refers to more specific
         * information.  However, there might only be one more specific entry
         * in the entire block, meaning the rest must be filled.
         *
         * For instance, imagine a 24-8 with 1.2.3/24 -> A and 1.2.3.4/32 -> B
         * There will be a pointer at 1.2.3 in the first table. The second
         * table needs to have 255 entries pointing A, and 1 entry pointing to
         * B.
         *
         * Therefore, recurse to this next level. */
        DIR_Entry* entry = (DIR_Entry*)(&base[subtable->entries]);
        if ( entry[index].value && !entry[index].length)
        {
            dir_sub_table_flat_t* next = (dir_sub_table_flat_t*)(&base[entry[index].value]);
            _dir_fill_less_specific(0, 1 << next->width, length, val, entry[index].value);
        }
        else if (length >= (unsigned)entry[index].length)
        {
            entry[index].value = val;
            entry[index].length = (char)length;
        }
    }
}

static inline int64_t _dir_update_info(int index, int fill,
    word length, uint32_t val, SUB_TABLE_PTR sub_ptr, updateEntryInfoFunc updateEntry, INFO* data)
{
    dir_sub_table_flat_t* subtable;
    uint8_t* base;
    int64_t bytesAllocatedTotal = 0;

    base = (uint8_t*)segment_basePtr();
    subtable = (dir_sub_table_flat_t*)(&base[sub_ptr]);

    /* Fill entries */
    for (; index < fill; index++)
    {
        /* If we encounter a pointer, and we're inserting at this level, we
         * automatically know that this entry refers to more specific
         * information.  However, there might only be one more specific entry
         * in the entire block, meaning the rest must be filled.
         *
         * For instance, imagine a 24-8 with 1.2.3/24 -> A and 1.2.3.4/32 -> B
         * There will be a pointer at 1.2.3 in the first table. The second
         * table needs to have 255 entries pointing A, and 1 entry pointing to
         * B.
         *
         * Therefore, recurse to this next level. */
        DIR_Entry* entry = (DIR_Entry*)(&base[subtable->entries]);
        if ( entry[index].value && !entry[index].length)
        {
            int64_t bytesAllocated;
            dir_sub_table_flat_t* next = (dir_sub_table_flat_t*)(&base[entry[index].value]);
            bytesAllocated = _dir_update_info(0, 1 << next->width, length, val,
                    entry[index].value, updateEntry, data);
            if (bytesAllocated < 0)
                return bytesAllocated;
            else
                bytesAllocatedTotal += bytesAllocated;
        }
        else if (length > (unsigned)entry[index].length)
        {
            if (entry[index].value)
            {
                int64_t bytesAllocated;
                bytesAllocated =  updateEntry(&data[entry[index].value], data[val],
                    SAVE_TO_NEW, base);
                if (bytesAllocated < 0)
                    return bytesAllocated;
                else
                    bytesAllocatedTotal += bytesAllocated;
            }

            entry[index].value = val;
            entry[index].length = (uint8_t)length;
        }
        else if (entry[index].value)
        {
            int64_t bytesAllocated;
            bytesAllocated = updateEntry(&data[entry[index].value], data[val],
                SAVE_TO_CURRENT,  base);
            if (bytesAllocated < 0)
                return bytesAllocated;
            else
                bytesAllocatedTotal += bytesAllocated;
        }
    }

    return bytesAllocatedTotal;
}

/* Sub table insertion
 * This is called by dir_insert and recursively to find the the sub table
 * that should house the value "ptr"
 * @param ip        IP address structure
 * @param cur_len   Number of bits of the IP left at this depth
 * @param length    Number of bits of the IP used to specify this CIDR
 * @param ptr       Information to be associated with this IP range
 * @param master_table    The table that describes all, returned by dir_new */
static int _dir_sub_insert(IPLOOKUP* ip, int length, int cur_len, INFO ptr,
    int current_depth, int behavior,
    SUB_TABLE_PTR sub_ptr, dir_table_flat_t* root_table,updateEntryInfoFunc updateEntry,
    INFO* data)
{
    word index;
    uint8_t* base = (uint8_t*)segment_basePtr();
    dir_sub_table_flat_t* sub_table = (dir_sub_table_flat_t*)(&base[sub_ptr]);

    {
        uint32_t local_index, i;
        /* need to handle bits usage across multiple 32bit vals within IPv6. */
        if (ip->bits < 32)
        {
            i=0;
        }
        else if (ip->bits < 64)
        {
            i=1;
        }
        else if (ip->bits < 96)
        {
            i=2;
        }
        else
        {
            i=3;
        }
        local_index = ip->addr[i] << (ip->bits % 32);
        index = local_index >> (ARCH_WIDTH - sub_table->width);
    }

    /* Check if this is the last table to traverse to */
    if (sub_table->width >= cur_len)
    {
        /* Calculate how many entries need to be filled
         * in this table. If the table is 24 bits wide, and the entry
         * is 20 bytes long, 2^4 entries need to be filled. */
        uint32_t fill = 1 << (sub_table->width - cur_len);

        index = (index >> (sub_table->width - cur_len)) <<
            (sub_table->width - cur_len);

        fill += index;

        /* Favor most recent CIDR */
        if (behavior == RT_FAVOR_TIME)
        {
            _dir_fill_all(&root_table->allocated, index, fill, length,
                (word)ptr, sub_ptr);
        }
        /* Fill over less specific CIDR */
        else if (behavior == RT_FAVOR_SPECIFIC)
        {
            _dir_fill_less_specific(index, fill, length, (word)ptr, sub_ptr);
        }
        else if (behavior == RT_FAVOR_ALL)
        {
            int64_t bytesAllocated;

            bytesAllocated = _dir_update_info(index, fill, length, (word)ptr,
                sub_ptr, updateEntry, data);

            if (bytesAllocated < 0)
                return MEM_ALLOC_FAILURE;

            root_table->allocated += (uint32_t)bytesAllocated;

            if ( root_table->mem_cap < root_table->allocated)
                return MEM_ALLOC_FAILURE;
        }
    }
    /* Need to traverse to a sub-table */
    else
    {
        DIR_Entry* entry = (DIR_Entry*)(&base[sub_table->entries]);

        /* Check if we need to alloc a new sub table.
         * If next_sub was 0/NULL, there's no entry at this index
         * If the length is non-zero, there is an entry */
        if (!entry[index].value || entry[index].length)
        {
            if ( root_table->dim_size <= current_depth )
            {
                return RT_INSERT_FAILURE;
            }

            entry[index].value =
                (word)_sub_table_flat_new(root_table, current_depth+1,
                (word)entry[index].value, entry[index].length);

            sub_table->cur_num++;

            entry[index].length = 0;

            if (!entry[index].value)
            {
                return MEM_ALLOC_FAILURE;
            }
        }
        /* Recurse to next level.  Rightshift off appropriate number of
         * bits and update the length accordingly. */
        ip->bits += sub_table->width;
        return (_dir_sub_insert(ip, length,
               cur_len - sub_table->width, ptr, current_depth+1,
               behavior, entry[index].value, root_table, updateEntry, data));
    }

    return RT_SUCCESS;
}

/* Insert entry into DIR-n-m tables */
int sfrt_dir_flat_insert(const uint32_t* addr, int /* numAddrDwords */, int len, word data_index,
    int behavior, TABLE_PTR table_ptr, updateEntryInfoFunc updateEntry, INFO* data)
{
    dir_table_flat_t* root;
    uint8_t* base;
    uint32_t h_addr[4];
    IPLOOKUP iplu;
    iplu.addr = h_addr;
    iplu.bits = 0;

    base = (uint8_t*)segment_basePtr();
    root = (dir_table_flat_t*)(&base[table_ptr]);
    /* Validate arguments */
    if (!root || !root->sub_table)
    {
        return DIR_INSERT_FAILURE;
    }

    h_addr[0] = ntohl(addr[0]);
    if (len > 96)
    {
        h_addr[1] = ntohl(addr[1]);
        h_addr[2] = ntohl(addr[2]);
        h_addr[3] = ntohl(addr[3]);
    }
    else if (len > 64)
    {
        h_addr[1] = ntohl(addr[1]);
        h_addr[2] = ntohl(addr[2]);
        h_addr[3] = 0;
    }
    else if (len > 32)
    {
        h_addr[1] = ntohl(addr[1]);
        h_addr[2] = 0;
        h_addr[3] = 0;
    }
    else
    {
        h_addr[1] = 0;
        h_addr[2] = 0;
        h_addr[3] = 0;
    }

    /* Find the sub table in which to insert */
    return _dir_sub_insert(&iplu, len, len, data_index,
        0, behavior, root->sub_table, root, updateEntry, data);
}

/* Traverse sub tables looking for match
   Called by dir_lookup and recursively */
static tuple_flat_t _dir_sub_flat_lookup(IPLOOKUP* ip, TABLE_PTR table_ptr)
{
    word index;
    uint8_t* base = (uint8_t*)segment_basePtr();
    DIR_Entry* entry;
    dir_sub_table_flat_t* table = (dir_sub_table_flat_t*)(&base[table_ptr]);

    {
        uint32_t local_index, i;
        /* need to handle bits usage across multiple 32bit vals within IPv6. */
        if (ip->bits < 32)
        {
            i=0;
        }
        else if (ip->bits < 64)
        {
            i=1;
        }
        else if (ip->bits < 96)
        {
            i=2;
        }
        else
        {
            i=3;
        }
        local_index = ip->addr[i] << (ip->bits %32);
        index = local_index >> (ARCH_WIDTH - table->width);
    }
    entry = (DIR_Entry*)(&base[table->entries]);

    if ( !entry[index].value || entry[index].length )
    {
        tuple_flat_t ret;
        ret.index = entry[index].value;
        ret.length = (word)entry[index].length;
        return ret;
    }

    ip->bits += table->width;
    return _dir_sub_flat_lookup(ip, entry[index].value);
}

/* Lookup information associated with the value "ip" */
tuple_flat_t sfrt_dir_flat_lookup(const uint32_t* addr, int numAddrDwords, TABLE_PTR table_ptr)
{
    dir_table_flat_t* root;
    uint8_t* base = (uint8_t*)segment_basePtr();
    uint32_t h_addr[4];
    int i;
    IPLOOKUP iplu;
    iplu.addr = h_addr;
    iplu.bits = 0;

    if (!table_ptr)
    {
        tuple_flat_t ret = { 0, 0 };
        return ret;
    }

    root = (dir_table_flat_t*)(&base[table_ptr]);

    if (!root->sub_table)
    {
        tuple_flat_t ret = { 0, 0 };
        return ret;
    }

    for (i = 0; i < numAddrDwords; i++)
        h_addr[i] = ntohl(addr[i]);
    while (i < 4)
        h_addr[i++] = 0;

    return _dir_sub_flat_lookup(&iplu, root->sub_table);
}

uint32_t sfrt_dir_flat_usage(TABLE_PTR table_ptr)
{
    dir_table_flat_t* table;
    uint8_t* base;
    if (!table_ptr)
    {
        return 0;
    }
    base = (uint8_t*)segment_basePtr();
    table = (dir_table_flat_t*)(&base[table_ptr]);
    return ((dir_table_flat_t*)(table))->allocated;
}

