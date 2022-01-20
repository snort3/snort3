//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// http2_huffman_state_machine.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_HUFFMAN_STATE_MACHINE_H
#define HTTP2_HUFFMAN_STATE_MACHINE_H

#include "main/snort_types.h"

enum HuffmanState
{
    HUFFMAN_LOOKUP_1 = 0,
    HUFFMAN_LOOKUP_2 = 1,
    HUFFMAN_LOOKUP_3 = 2,
    HUFFMAN_LOOKUP_4 = 3,
    HUFFMAN_LOOKUP_5 = 4,
    HUFFMAN_LOOKUP_6 = 5,
    HUFFMAN_LOOKUP_7 = 6,
    HUFFMAN_LOOKUP_8 = 7,
    HUFFMAN_LOOKUP_9 = 8,
    HUFFMAN_LOOKUP_10 = 9,
    HUFFMAN_LOOKUP_11 = 10,
    HUFFMAN_LOOKUP_12 = 11,
    HUFFMAN_LOOKUP_13 = 12,
    HUFFMAN_LOOKUP_14 = 13,
    HUFFMAN_LOOKUP_15 = 14,
    HUFFMAN_LOOKUP_MAX = HUFFMAN_LOOKUP_15,
    HUFFMAN_MATCH = HUFFMAN_LOOKUP_MAX + 1,
    HUFFMAN_FAILURE = HUFFMAN_MATCH + 1
};

struct HuffmanEntry
{
    uint8_t len;
    char symbol;
    HuffmanState state;
};

extern const HuffmanEntry huffman_decode[][UINT8_MAX+1];

#endif

