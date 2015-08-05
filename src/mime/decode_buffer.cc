//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "decode_buffer.h"

#include "utils/snort_bounds.h"
#include "utils/util.h"


void DecodeBuffer::reset()
{
    prev_encoded_bytes = 0;
    prev_encoded_buf = nullptr;
}

// 1. Stop decoding when we have reached either the decode depth or encode depth.
// 2. Stop decoding when we are out of memory
bool DecodeBuffer::is_buffer_available(uint32_t& encode_avail, uint32_t& decode_avail)
{
    if (!(encode_depth))
    {
        encode_avail = decode_avail = buf_size;
    }
    else
    {
        encode_avail = encode_depth - encode_bytes_read;
        decode_avail = decode_depth - decode_bytes_read;
    }

    if (encode_avail ==0 || decode_avail ==0 ||
        (!encodeBuf) || (!decodeBuf))
    {
        return false;
    }

    return true;
}

#define MAX_DEPTH       65536

DecodeBuffer::DecodeBuffer(int max_depth)
{
    if (!max_depth)
        buf_size = MAX_DEPTH;
    else
        buf_size = max_depth;

    encode_depth = decode_depth = max_depth;
    encode_bytes_read = decode_bytes_read = 0;
    prev_encoded_bytes = 0;
    prev_encoded_buf = nullptr;

    if (max_depth < 0)
        return;

    encodeBuf = (uint8_t*)SnortAlloc(buf_size);
    decodeBuf = (uint8_t*)SnortAlloc(buf_size);
}

DecodeBuffer::~DecodeBuffer()
{
    if (encodeBuf)
        free(encodeBuf);
    if (decodeBuf)
        free(decodeBuf);
}

void DecodeBuffer::resume_decode(uint32_t& encode_avail, uint32_t& prev_bytes)
{
    uint32_t i = 0;

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of data spanned across packets*/

    if ( !prev_encoded_bytes )
        return;

    if (prev_encoded_bytes > encode_avail)
        prev_encoded_bytes = encode_avail;

    if (prev_encoded_buf)
    {
        prev_bytes = prev_encoded_bytes;
        encode_avail = encode_avail - prev_bytes;
        while (prev_encoded_bytes)
        {
            encodeBuf[i] = prev_encoded_buf[i];
            i++;
            prev_encoded_bytes--;
        }
    }
}

void DecodeBuffer::update_buffer(uint32_t act_encode_size, uint32_t act_decode_size)
{
    encode_bytes_read += act_encode_size;
    decode_bytes_read += act_decode_size;
}

void DecodeBuffer::save_buffer(uint8_t* buff, uint32_t buff_size)
{
    prev_encoded_bytes = buff_size;
    prev_encoded_buf = buff;
}
