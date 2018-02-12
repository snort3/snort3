//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// decode_bit.cc author Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode_bit.h"

void BitDecode::reset_decode_state()
{
    reset_decoded_bytes();
}

DecodeResult BitDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    uint32_t bytes_avail = 0;
    uint32_t act_size = end - start;

    if (!(decode_depth))
    {
        bytes_avail = act_size;
    }
    else if ( (uint32_t)decode_depth > decode_bytes_read )
    {
        bytes_avail = (uint32_t)decode_depth - decode_bytes_read;
    }
    else
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    if ( act_size > bytes_avail )
    {
        act_size = bytes_avail;
    }

    decoded_bytes = act_size;
    decodePtr = start;
    decode_bytes_read += act_size;

    return DECODE_SUCCESS;
}

BitDecode::BitDecode(int max_depth, int detect_depth) : DataDecode(max_depth, detect_depth)
{
    decode_depth = max_depth;
    decode_bytes_read = 0;
    decoded_bytes = 0;
}


