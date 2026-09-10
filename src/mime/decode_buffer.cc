//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// decode_buffer.cc author Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode_buffer.h"

#include <algorithm>
#include <cstring>
#include <new>

#include "file_mime_config.h"

void DecodeBuffer::reset_saved()
{
    prev_encoded_bytes = 0;
    prev_encoded_offset = 0;
}

DecodeBuffer::RestoreResult DecodeBuffer::check_restore_buffer(uint32_t in_bytes)
{
    // 1. Stop decoding when we have reached either the decode depth or encode depth.
    // 2. Stop decoding when we are out of memory

    if (!in_bytes)
        return RestoreResult::NO_INPUT;

    if (code_depth < 0)
        return RestoreResult::EXCEEDED;

    uint32_t decode_avail = get_decode_avail();

    uint32_t encode_avail = raw_encode_avail();

    if (encode_avail ==0 || decode_avail ==0)
        return RestoreResult::EXCEEDED;

    const uint32_t max_stage = std::min(encode_avail, buf_size);
    const uint64_t needed = static_cast<uint64_t>(prev_encoded_bytes) + in_bytes;
    const uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(needed, max_stage));

    if (want > encodeBuf.size())
    {
        try
        {
            encodeBuf.reserve(want);
            encodeBuf.resize(want);
        }
        catch (const std::bad_alloc&)
        {
            return RestoreResult::EXCEEDED;
        }
    }

    /*The non decoded encoded data in the previous packet is required for successful decoding
     * in case of data spanned across packets*/

    if ( !prev_encoded_bytes )
        return RestoreResult::READY;

    if (prev_encoded_bytes > encode_avail)
        prev_encoded_bytes = encode_avail;

    memmove(encodeBuf.data(), encodeBuf.data() + prev_encoded_offset, prev_encoded_bytes);
    prev_encoded_offset = 0;

    return RestoreResult::READY;
}

uint32_t DecodeBuffer::get_decode_avail()
{
    uint32_t avail;

    if (!(code_depth))
        avail = buf_size;
    else
        avail = code_depth - decode_bytes_read;

    if (avail > MAX_DEPTH)
        avail = MAX_DEPTH;

    return avail;
}

uint32_t DecodeBuffer::raw_encode_avail()
{
    if (!(code_depth))
    {
        return buf_size;
    }
    else
    {
        return (code_depth - encode_bytes_read);
    }
}

uint32_t DecodeBuffer::get_encode_avail()
{
    return std::min(raw_encode_avail(), static_cast<uint32_t>(encodeBuf.size()));
}

DecodeBuffer::DecodeBuffer(int max_depth)
{
    if (!max_depth)
        buf_size = MAX_DEPTH;
    else
        buf_size = max_depth;

    code_depth = max_depth;
}

void DecodeBuffer::update_buffer(uint32_t act_encode_size, uint32_t act_decode_size)
{
    encode_bytes_read += act_encode_size;
    decode_bytes_read += act_decode_size;
}

void DecodeBuffer::save_buffer(uint32_t offset, uint32_t buff_size)
{
    prev_encoded_offset = offset;
    prev_encoded_bytes = buff_size;
}
