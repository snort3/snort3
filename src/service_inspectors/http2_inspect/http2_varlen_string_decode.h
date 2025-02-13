//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_varlen_string_decode.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_VARLEN_STRING_DECODE_H
#define HTTP2_VARLEN_STRING_DECODE_H

#include "main/snort_types.h"

template <typename IntDec, typename EGen, typename Inf>
class VarLengthStringDecode
{
public:
    // huffman_mask for string literals in HPACK is always 0x80, thus defaulting
    // to 0x80
    bool translate(const uint8_t* in_buff, const uint32_t in_len,
        IntDec& decode_int, uint32_t& bytes_consumed,
        uint8_t* out_buff, const uint32_t out_len, uint32_t& bytes_written,
        EGen* const events, Inf* const infractions,
        bool partial_header, uint8_t huffman_mask = 0x80) const;

private:
    bool get_string(const uint8_t* in_buff, const uint32_t encoded_len, uint32_t& bytes_consumed,
        uint8_t* out_buff, const uint32_t out_len, uint32_t& bytes_written,
        Inf* const infractions) const;
    bool get_huffman_string(const uint8_t* in_buff, const uint32_t encoded_len,
        uint32_t& bytes_consumed, uint8_t* out_buff, const uint32_t out_len, uint32_t&
        bytes_written, Inf* const infractions) const;
    bool get_next_byte(const uint8_t* in_buff, const uint32_t last_byte,
        uint32_t& bytes_consumed, uint8_t& cur_bit, uint8_t match_len, uint8_t& byte,
        bool& another_search) const;
};

#endif

