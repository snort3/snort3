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
// http2_varlen_int_decode.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP2_VARLEN_INT_DECODE_H
#define HTTP2_VARLEN_INT_DECODE_H

#include "main/snort_types.h"

template <typename EGen, typename Inf>
class VarLengthIntDecode
{
public:
    VarLengthIntDecode(uint8_t prefix);
    bool translate(const uint8_t* in_buff, const uint32_t in_len, uint32_t& bytes_consumed,
        uint64_t& result, EGen* const events, Inf* const infractions,
        bool partial_header) const;

private:
    const uint8_t prefix_mask;
};

#endif

