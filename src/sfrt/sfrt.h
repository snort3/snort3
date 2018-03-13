//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// A 32-bit word is used to hold the bit patterns of the addresses.
// In IPv6 this should be 128 bits.  The following typedef is
// machine dependent.  A word must be 32 bits long!
typedef unsigned long word;

typedef void* GENERIC;  // To be replaced with a pointer to a policy

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

enum
{
    RT_FAVOR_TIME,
    RT_FAVOR_SPECIFIC,
    RT_FAVOR_ALL
};

extern const char* rt_error_messages[];

typedef int (* table_insert)(
    const uint32_t* addr, int numAddrDwords, int len, word index, int behavior, GENERIC);

typedef word (* table_remove)(
    const uint32_t* addr, int numAddrDwords, int len, int behavior, GENERIC);

typedef tuple_t (* table_lookup)(const uint32_t* addr, int numAddrDwords, GENERIC);

typedef uint32_t (* table_usage)(GENERIC);
typedef void (* table_print)(GENERIC);
typedef void (* table_free)(GENERIC);

// Master table struct.  Abstracts DIR and LC-trie methods
struct table_t
{
    GENERIC* data;               // data table. Each IP points to an entry here
    uint32_t num_ent;            // Number of entries in the policy table
    uint32_t max_size;           // Max size of policies array
    uint32_t lastAllocatedIndex; // Index allocated last. Search for unused index
                                 // starts from this value and then wraps around at max_size.
    char ip_type;                // Only IPs of this family will be used
    char table_type;
    uint32_t allocated;

    void* rt;                    // Actual "routing" table
    void* rt6;                   // Actual "routing" table

    table_insert insert;
    table_remove remove;
    table_lookup lookup;
    table_usage usage;
    table_print print;
    table_free free;
};

// Abstracted routing table API
table_t* sfrt_new(char type, char ip_type, long data_size, uint32_t mem_cap);
void sfrt_free(table_t*);

GENERIC sfrt_lookup(const snort::SfIp*, table_t*);
GENERIC sfrt_search(const snort::SfIp*, unsigned char len, table_t*);

typedef void (* sfrt_iterator_callback)(void*);
void sfrt_cleanup(table_t*, sfrt_iterator_callback);

int sfrt_insert(snort::SfCidr*, unsigned char len, GENERIC, int behavior, table_t*);
int sfrt_remove(snort::SfCidr*, unsigned char len, GENERIC*, int behavior, table_t*);

uint32_t sfrt_usage(table_t*);
void sfrt_print(table_t*);
uint32_t sfrt_num_entries(table_t*);

#endif

