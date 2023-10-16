//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
// http2_varlen_int_decode_impl.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_VARLEN_INT_DECODE_IMPL_H
#define HTTP2_VARLEN_INT_DECODE_IMPL_H

#include <cassert>

#include "main/snort_types.h"

template <typename EGen, typename Inf>
VarLengthIntDecode<EGen, Inf>::VarLengthIntDecode(uint8_t prefix) : prefix_mask(((uint16_t)1 << prefix) - 1)
{
    assert ((0 < prefix) && (prefix < 9));
}

template <typename EGen, typename Inf>
bool VarLengthIntDecode<EGen, Inf>::translate(const uint8_t* in_buff, const uint32_t in_len,
    uint32_t& bytes_consumed, uint64_t& result, EGen* const events,
    Inf* const infractions, bool partial_header) const
{
    const uint8_t VAL_MASK = 0x7F;
    const uint8_t FLAG_BIT = 0x80;

    bytes_consumed = 0;
    result = 0;

    if (in_len == 0)
    {
        if (!partial_header)
            *infractions += INF_INT_EMPTY_BUFF;
        else
            *infractions += INF_TRUNCATED_HEADER_LINE;
        return false;
    }

    const uint8_t prefix_val = in_buff[bytes_consumed++] & prefix_mask;

    if (prefix_val < prefix_mask)
    {
        result = prefix_val;
        return true;
    }

    uint8_t byte = 0;
    for (uint8_t multiplier = 0; multiplier < 64; multiplier += 7)
    {
        if (bytes_consumed >= in_len)
        {
            if (!partial_header)
                *infractions += INF_INT_MISSING_BYTES;
            else
                *infractions += INF_TRUNCATED_HEADER_LINE;
            return false;
        }
        byte = in_buff[bytes_consumed++];

        // For multiplier == 63, do overflow checks
        if (multiplier == 63)
        {
            if (((byte & FLAG_BIT) != 0) || ((byte & VAL_MASK) > 1) ||
                ((result + ((uint64_t)(byte & VAL_MASK) << multiplier) + prefix_mask) < result))
            {
                *infractions += INF_INT_OVERFLOW;
                return false;
            }
        }

        result += (uint64_t)(byte & VAL_MASK) << multiplier;

        if ((byte & FLAG_BIT) == 0)
            break;
    }

    // Alert on leading 0s, allow for value 2^N-1
    if (((byte & VAL_MASK) == 0) && (bytes_consumed != 2))
    {
        *infractions += INF_INT_LEADING_ZEROS;
        events->create_event(EVENT_INT_LEADING_ZEROS);
    }

    result += prefix_mask;

    return true;
}

#endif

