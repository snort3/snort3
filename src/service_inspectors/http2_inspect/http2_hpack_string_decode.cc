//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// http2_hpack_string_decode.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_hpack_string_decode.h"

#include "http2_enum.h"

using namespace Http2Enums;

static const uint8_t HUFFMAN_FLAG = 0x80;

Http2HpackStringDecode::Http2HpackStringDecode(Http2EventGen* events,
    Http2Infractions* infractions) : decode7(new Http2HpackIntDecode(7, events, infractions)),
    events(events), infractions(infractions)
{ }

bool Http2HpackStringDecode::translate(const uint8_t* in_buff, const uint32_t in_len,
    uint32_t& bytes_consumed, uint8_t* out_buff, const uint32_t out_len, uint32_t& bytes_written)
{
    bytes_consumed = 0;
    bytes_written = 0;

    if (in_len == 0)
    {
        *infractions += INF_STRING_EMPTY_BUFF;
        events->create_event(EVENT_STRING_DECODE_FAILURE);
        return false;
    }

    const bool isHuffman = (in_buff[0] & HUFFMAN_FLAG) != 0;

    // Get length
    uint64_t encoded_len;
    if (!decode7->translate(in_buff, in_len, bytes_consumed, encoded_len))
        return false;

    if (encoded_len > (uint64_t)(in_len - bytes_consumed))
    {
        *infractions += INF_STRING_MISSING_BYTES;
        events->create_event(EVENT_STRING_DECODE_FAILURE);
        return false;
    }

    if (encoded_len == 0)
        return true;

    if (!isHuffman)
        return get_string(in_buff, encoded_len, bytes_consumed, out_buff, out_len, bytes_written);

    return get_huffman_string(in_buff, encoded_len, bytes_consumed, out_buff, out_len,
        bytes_written);
}

Http2HpackStringDecode::~Http2HpackStringDecode()
{
    assert(decode7 != nullptr);
    delete decode7;
}

bool Http2HpackStringDecode::get_string(const uint8_t* in_buff, const uint32_t encoded_len,
    uint32_t& bytes_consumed, uint8_t* out_buff, const uint32_t out_len, uint32_t& bytes_written)
{
    if (encoded_len > out_len)
    {
        *infractions += INF_OUT_BUFF_OUT_OF_SPACE;
        events->create_event(EVENT_STRING_DECODE_FAILURE);
        return false;
    }

    while (bytes_written < encoded_len)
        out_buff[bytes_written++] = in_buff[bytes_consumed++];

    return true;
}

bool Http2HpackStringDecode::get_huffman_string(const uint8_t*, const uint32_t, uint32_t&,
    uint8_t*, const uint32_t, uint32_t&) { return false; }

