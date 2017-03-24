//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include <cstdint>

#include "sfip/sf_ip.h"

/* A 32-bit word is used to hold the bit patterns of
   the addresses. In IPv6 this should be 128 bits.
   The following typedef is machine dependent.
   A word must be 32 bits long! */
typedef unsigned long word;

typedef void* GENERIC;   /* To be replaced with a pointer to a policy */
struct tuple_t
{
    word index;
    word length;
};

#include "sfrt/sfrt_dir.h"

enum types
{
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

    tuple_t (* lookup)(const uint32_t* addr, int numAddrDwords, GENERIC tbl);
    int (* insert)(const uint32_t* addr, int numAddrDwords, int len, word index, int behavior, GENERIC tbl);
    void (* free)(GENERIC tbl);
    uint32_t (* usage)(GENERIC tbl);
    void (* print)(GENERIC tbl);
    word (* remove)(const uint32_t* addr, int numAddrDwords, int len, int behavior, GENERIC tbl);
} table_t;
/*******************************************************************/

/* Abstracted routing table API */
table_t* sfrt_new(char type, char ip_type, long data_size, uint32_t mem_cap);
void sfrt_free(table_t* table);
GENERIC sfrt_lookup(const SfIp* ip, table_t* table);
GENERIC sfrt_search(const SfIp* ip, unsigned char len, table_t* table);
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
int sfrt_insert(SfCidr* cidr, unsigned char len, GENERIC ptr,
    int behavior, table_t* table);
int sfrt_remove(SfCidr* cidr, unsigned char len, GENERIC* ptr,
    int behavior, table_t* table);
uint32_t sfrt_usage(table_t* table);
void sfrt_print(table_t* table);
uint32_t sfrt_num_entries(table_t* table);

#endif
