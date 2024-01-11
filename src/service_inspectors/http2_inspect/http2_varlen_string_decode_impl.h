//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_varlen_string_decode_impl.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_VARLEN_STRING_DECODE_IMPL_H
#define HTTP2_VARLEN_STRING_DECODE_IMPL_H

#include "http2_huffman_state_machine.h"
#include "http2_varlen_string_decode.h"

#include <cmath>

// Minimum bit length for each lookup table
static const uint8_t min_decode_len[HUFFMAN_LOOKUP_MAX + 1] =
    {5, 2, 2, 3, 5, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4};

template <typename IntDec, typename EGen, typename Inf>
bool VarLengthStringDecode<IntDec, EGen, Inf>::translate(const uint8_t* in_buff, const uint32_t in_len,
    IntDec& decode_int, uint32_t& bytes_consumed, uint8_t* out_buff,
    const uint32_t out_len, uint32_t& bytes_written,
    EGen* const events, Inf* const infractions, bool partial_header,
    uint8_t huffman_mask) const
{
    bytes_consumed = 0;
    bytes_written = 0;

    if (in_len == 0)
    {
        if (!partial_header)
            *infractions += INF_STRING_EMPTY_BUFF;
        else
            *infractions += INF_TRUNCATED_HEADER_LINE;
        return false;
    }

    const bool isHuffman = (in_buff[0] & huffman_mask) != 0;

    // Get length
    uint64_t encoded_len;
    if (!decode_int.translate(in_buff, in_len, bytes_consumed, encoded_len, events, infractions,
            partial_header))
        return false;

    if (encoded_len > (uint64_t)(in_len - bytes_consumed))
    {
        if (!partial_header)
            *infractions += INF_STRING_MISSING_BYTES;
        else
            *infractions += INF_TRUNCATED_HEADER_LINE;
        return false;
    }

    if (encoded_len == 0)
        return true;

    if (!isHuffman)
        return get_string(in_buff, encoded_len, bytes_consumed, out_buff, out_len, bytes_written,
            infractions);

    return get_huffman_string(in_buff, encoded_len, bytes_consumed, out_buff, out_len,
        bytes_written, infractions);
}

template <typename IntDec, typename EGen, typename Inf>
bool VarLengthStringDecode<IntDec, EGen, Inf>::get_string(const uint8_t* in_buff, const uint32_t encoded_len,
    uint32_t& bytes_consumed, uint8_t* out_buff, const uint32_t out_len, uint32_t& bytes_written,
    Inf* const infractions) const
{
    if (encoded_len > out_len)
    {
        *infractions += INF_DECODED_HEADER_BUFF_OUT_OF_SPACE;
        return false;
    }

    while (bytes_written < encoded_len)
        out_buff[bytes_written++] = in_buff[bytes_consumed++];

    return true;
}

// return is tail/padding
template <typename IntDec, typename EGen, typename Inf>
bool VarLengthStringDecode<IntDec, EGen, Inf>::get_next_byte(const uint8_t* in_buff, const uint32_t last_byte,
    uint32_t& bytes_consumed, uint8_t& cur_bit, uint8_t match_len, uint8_t& byte,
    bool& another_search) const
{
    another_search = true;
    cur_bit += match_len;

    if (cur_bit >= 8) // done with current bit
    {
        bytes_consumed++;
        cur_bit -= 8;
    }

    bool tail = false;
    uint8_t msb, lsb = 0xff;
    if (bytes_consumed == last_byte)
    {
        // bytes consumed must be bigger than 1 - int length is at least 1
        msb = in_buff[bytes_consumed-1];
        another_search = false;
        tail = true;
    }
    else if ((bytes_consumed + 1) == last_byte)
    {
        if (cur_bit != 0)
        {
            msb = in_buff[bytes_consumed++];
            tail = true;
        }
        else
        {
            byte = in_buff[bytes_consumed];
            return false;
        }
    }
    else
    {
        msb = in_buff[bytes_consumed];
        lsb = in_buff[bytes_consumed+1];
    }

    const uint16_t tmp = (uint16_t)(msb << 8) | lsb;
    byte = (tmp & (0xff00 >> cur_bit)) >> (8 - cur_bit);
    return tail;
}

template <typename IntDec, typename EGen, typename Inf>
bool VarLengthStringDecode<IntDec, EGen, Inf>::get_huffman_string(const uint8_t* in_buff, const uint32_t encoded_len,
    uint32_t& bytes_consumed, uint8_t* out_buff, const uint32_t out_len, uint32_t& bytes_written,
    Inf* const infractions) const
{
    const uint32_t last_encoded_byte = bytes_consumed + encoded_len;
    uint8_t byte;
    uint8_t cur_bit = 0;
    HuffmanEntry result = { 0, 0, HUFFMAN_LOOKUP_1 };
    bool another_search = false;
    HuffmanState state = HUFFMAN_LOOKUP_1;

    // Check length
    const uint32_t max_length = floor(encoded_len * 8.0/5.0);
    if (max_length > out_len)
    {
        *infractions += INF_DECODED_HEADER_BUFF_OUT_OF_SPACE;
        return false;
    }

    while (!get_next_byte(in_buff, last_encoded_byte, bytes_consumed, cur_bit, result.len, byte,
        another_search))
    {
        result = huffman_decode[state][byte];

        switch (result.state) {

        case HUFFMAN_MATCH:
            out_buff[bytes_written++] = result.symbol;
            state = HUFFMAN_LOOKUP_1;
            break;

        case HUFFMAN_LOOKUP_2:
        case HUFFMAN_LOOKUP_3:
        case HUFFMAN_LOOKUP_4:
        case HUFFMAN_LOOKUP_5:
        case HUFFMAN_LOOKUP_6:
        case HUFFMAN_LOOKUP_7:
        case HUFFMAN_LOOKUP_8:
        case HUFFMAN_LOOKUP_9:
        case HUFFMAN_LOOKUP_10:
        case HUFFMAN_LOOKUP_11:
        case HUFFMAN_LOOKUP_12:
        case HUFFMAN_LOOKUP_13:
        case HUFFMAN_LOOKUP_14:
        case HUFFMAN_LOOKUP_15:
            state = result.state;
            break;

        case HUFFMAN_FAILURE:
            *infractions += INF_HUFFMAN_DECODED_EOS;
            return false;

        default:
            break;
        }
    }

    // Tail needs 1 last lookup in case the leftover is big enough for a match.
    // Make sure match length <= available length
    uint8_t leftover_len = 8 - cur_bit;
    uint8_t old_result_len = result.len;
    HuffmanState old_result_state = result.state;

    if (another_search && (leftover_len >= min_decode_len[state]))
    {
        result = huffman_decode[state][byte];
        if ((result.state == HUFFMAN_MATCH) && (result.len <= leftover_len))
        {
            out_buff[bytes_written++] = result.symbol;
            byte = (byte << result.len) | (((uint16_t)1 << result.len) - 1);
        }
        else
        {
            // Use leftover bits for padding check if previous lookup was a match
            if (old_result_state == HUFFMAN_MATCH)
                result.len = leftover_len;
            else
                result.len = old_result_len;
        }
    }

    // Padding check
    if (result.len < 8)
    {
        if (byte != 0xff)
        {
            *infractions += INF_HUFFMAN_BAD_PADDING;
            return false;
        }
    }
    else if (result.state != HUFFMAN_MATCH)
    {
        *infractions += INF_HUFFMAN_INCOMPLETE_CODE_PADDING;
        return false;
    }

    return true;
}

#endif

