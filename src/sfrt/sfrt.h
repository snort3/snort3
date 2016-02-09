//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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

// sfrt.h author Adam Keeton <akeeton@sourcefire.com>
// Thu July 20 10:16:26 EDT 2006

#ifndef SFRT_H
#define SFRT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <sys/types.h>

#include "main/snort_debug.h"
#include "sfrt/sfrt_trie.h"
#include "sfip/sfip_t.h"

typedef sfip_t* IP;
typedef void* GENERIC;   /* To be replaced with a pointer to a policy */
struct tuple_t
{
    word index;
    word length;
};

#include "sfrt/sfrt_dir.h"
//#define SUPPORT_LCTRIE
#ifdef SUPPORT_LCTRIE
#include "sfrt/sfrt_lctrie.h"
#endif

enum types
{
#ifdef SUPPORT_LCTRIE
    LCT,
#endif
    DIR_24_8,
    DIR_16x2,
    DIR_16_8x2,
    DIR_16_4x4,
    DIR_8x4,
    DIR_4x8,
    DIR_2x16,
    DIR_16_4x4_16x5_4x4,
    DIR_16x7_4x4,
    DIR_16x8,
    DIR_8x16,
    IPv4,
    IPv6
};

enum return_codes
{
    RT_SUCCESS=0,
    RT_INSERT_FAILURE,
    RT_POLICY_TABLE_EXCEEDED,
    DIR_INSERT_FAILURE,
    DIR_LOOKUP_FAILURE,
    MEM_ALLOC_FAILURE,
#ifdef SUPPORT_LCTRIE
    LCT_COMPILE_FAILURE,
    LCT_INSERT_FAILURE,
    LCT_LOOKUP_FAILURE,
#endif
    RT_REMOVE_FAILURE
};

/* Defined in sfrt.c */
extern const char* rt_error_messages[];

enum
{
    RT_FAVOR_TIME,
    RT_FAVOR_SPECIFIC,
    RT_FAVOR_ALL
};

/******************************************************************
   Master table struct.  Abstracts DIR and LC-trie methods         */
typedef struct
{
    GENERIC* data;      /* data table. Each IP points to an entry here */
    uint32_t num_ent;  /* Number of entries in the policy table */
    uint32_t max_size; /* Max size of policies array */
    uint32_t lastAllocatedIndex; /* Index allocated last. Search for unused index
                                    starts from this value and then wraps around at max_size.*/
    char ip_type;       /* Only IPs of this family will be used */
    char table_type;
    uint32_t allocated;

    void* rt;            /* Actual "routing" table */
    void* rt6;            /* Actual "routing" table */

    tuple_t (* lookup)(IP ip, GENERIC tbl);
    int (* insert)(IP ip, int len, word index, int behavior, GENERIC tbl);
    void (* free)(GENERIC tbl);
    uint32_t (* usage)(GENERIC tbl);
    void (* print)(GENERIC tbl);
    word (* remove)(IP ip, int len, int behavior, GENERIC tbl);
} table_t;
/*******************************************************************/

/* Abstracted routing table API */
table_t* sfrt_new(char type, char ip_type, long data_size, uint32_t mem_cap);
void sfrt_free(table_t* table);
GENERIC sfrt_lookup(sfip_t* ip, table_t* table);
GENERIC sfrt_search(sfip_t* ip, unsigned char len, table_t* table);
typedef void (* sfrt_iterator_callback)(void*);
struct SnortConfig;
typedef void (* sfrt_sc_iterator_callback)(SnortConfig*, void*);
typedef int (* sfrt_sc_iterator_callback3)(SnortConfig*, void*);
typedef void (* sfrt_iterator_callback2)(void*, void*);
typedef int (* sfrt_iterator_callback3)(void*);
void sfrt_iterate(table_t* table, sfrt_iterator_callback userfunc);
void sfrt_iterate_with_snort_config(SnortConfig* sc, table_t* table, sfrt_sc_iterator_callback
    userfunc);
int sfrt_iterate2(table_t* table, sfrt_iterator_callback3 userfunc);
int sfrt_iterate2_with_snort_config(SnortConfig* sc, table_t* table, sfrt_sc_iterator_callback3
    userfunc);
void sfrt_cleanup(table_t* table, sfrt_iterator_callback userfunc);
void sfrt_cleanup2(table_t*, sfrt_iterator_callback2, void*);
int sfrt_insert(sfip_t* ip, unsigned char len, GENERIC ptr,
    int behavior, table_t* table);
int sfrt_remove(sfip_t* ip, unsigned char len, GENERIC* ptr,
    int behavior, table_t* table);
uint32_t sfrt_usage(table_t* table);
void sfrt_print(table_t* table);
uint32_t sfrt_num_entries(table_t* table);

/* Perform a lookup on value contained in "ip"
 * For performance reason, we use this simplified version instead of sfrt_lookup
 * Note: this only applied to table setting: DIR_8x16 (DIR_16_8_4x2 for IPV4), DIR_8x4*/
inline GENERIC sfrt_dir8x_lookup(void* adr, table_t* table)
{
    dir_sub_table_t* subtable;
    int i;
    sfip_t* ip;
    void* rt = NULL;
    int index;

    ip = (sfip_t*)adr;
    if (ip->family == AF_INET)
    {
        rt =  table->rt;
        subtable = ((dir_table_t*)rt)->sub_table;
        /* 16 bits*/
        index = ntohs(ip->ip16[0]);
        if ( !subtable->entries[index] || subtable->lengths[index] )
        {
            return table->data[subtable->entries[index]];
        }
        subtable = (dir_sub_table_t*)subtable->entries[index];

        /* 8 bits*/
        index = ip->ip8[2];
        if ( !subtable->entries[index] || subtable->lengths[index] )
        {
            return table->data[subtable->entries[index]];
        }
        subtable = (dir_sub_table_t*)subtable->entries[index];

        /* 4 bits */
        index = ip->ip8[3] >> 4;
        if ( !subtable->entries[index] || subtable->lengths[index] )
        {
            return table->data[subtable->entries[index]];
        }
        subtable = (dir_sub_table_t*)subtable->entries[index];

        /* 4 bits */
        index = ip->ip8[3] & 0xF;
        if ( !subtable->entries[index] || subtable->lengths[index] )
        {
            return table->data[subtable->entries[index]];
        }
    }
    else if (ip->family == AF_INET6)
    {
        rt =  table->rt6;
        subtable = ((dir_table_t*)rt)->sub_table;
        for (i = 0; i < 16; i++)
        {
            index = ip->ip8[i];
            if ( !subtable->entries[index] || subtable->lengths[index] )
            {
                return table->data[subtable->entries[index]];
            }
            subtable = (dir_sub_table_t*)subtable->entries[index];
        }
    }
    return NULL;
}

#endif

