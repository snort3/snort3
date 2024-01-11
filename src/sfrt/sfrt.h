//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
using MEM_OFFSET = uint32_t;

struct tuple_t
{
    word index;
    word length;
};

enum types
{
#if 0
    // supporting code for these types (and RT_FAVOR_* below) is
    // disabled since it is not used. not deleting in case we need
    // switch types at some point. see sfrt_*.cc.
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
#endif
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
#if 0
    RT_FAVOR_TIME,
    RT_FAVOR_SPECIFIC,
#endif
    RT_FAVOR_ALL
};

#endif

