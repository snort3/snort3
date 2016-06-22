//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>

#include <mime/decode_base.h>
#include "decode_bit.h"

#include "utils/util.h"

void BitDecode::reset_decode_state()
{
    reset_decoded_bytes();
}

DecodeResult BitDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t bytes_avail = 0;
    uint32_t act_size = 0;

    if (!(decode_depth))
    {
        bytes_avail = buf_size;
    }
    else if ( decode_depth < 0 )
    {
        return DECODE_EXCEEDED;
    }
    else
    {
        bytes_avail = decode_depth - decode_bytes_read;
    }

    /* 1. Stop decoding when we have reached either the decode depth or encode depth.
     * 2. Stop decoding when we are out of memory */
    if (bytes_avail ==0)
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    if ( (uint32_t)(end-start) < bytes_avail )
    {
        act_size = ( end - start);
    }
    else
    {
        act_size = bytes_avail;
    }

    decoded_bytes = act_size;
    decodePtr = (uint8_t*)start;
    decode_bytes_read += act_size;

    return DECODE_SUCCESS;
}

#define MAX_DEPTH       65536

BitDecode::BitDecode(int max_depth):DataDecode(max_depth)
{
    if (!max_depth)
        buf_size = MAX_DEPTH;
    else
        buf_size = max_depth;
    decode_depth = max_depth;
    decode_bytes_read = 0;
    decoded_bytes = 0;
}

BitDecode::~BitDecode()
{

}


