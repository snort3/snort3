//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_normalizers.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_str_to_code.h"
#include "nhttp_normalizers.h"

using namespace NHttpEnums;

// Collection of stock normalization functions. This will probably grow throughout the life of the
// software. New functions must follow the standard signature. The void* at the end is for any
// special configuration data the function requires.

int32_t norm_decimal_integer(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions& infractions, NHttpEventGen&, const void*)
{
    // Limited to 18 decimal digits, not including leading zeros, to fit comfortably into int64_t
    int64_t total = 0;
    int non_leading_zeros = 0;
    for (int32_t k=0; k < in_length; k++)
    {
        int value = in_buf[k] - '0';
        if (non_leading_zeros || (value != 0))
            non_leading_zeros++;
        if (non_leading_zeros > 18)
        {
            infractions += INF_BAD_HEADER_DATA;
            return STAT_PROBLEMATIC;
        }
        if ((value < 0) || (value > 9))
        {
            infractions += INF_BAD_HEADER_DATA;
            return STAT_PROBLEMATIC;
        }
        total = total*10 + value;
    }
    ((int64_t*)out_buf)[0] = total;
    return sizeof(int64_t);
}

int32_t norm_to_lower(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions&, NHttpEventGen&, const void*)
{
    for (int32_t k=0; k < in_length; k++)
    {
        out_buf[k] = ((in_buf[k] < 'A') || (in_buf[k] > 'Z')) ? in_buf[k] : in_buf[k] - ('A' -
            'a');
    }
    return in_length;
}

int32_t norm_str_code(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions&, NHttpEventGen&, const void* table)
{
    ((int64_t*)out_buf)[0] = str_to_code(in_buf, in_length, (const StrCode*)table);
    return sizeof(int64_t);
}

int32_t norm_seq_str_code(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions&, NHttpEventGen&, const void* table)
{
    int32_t num_codes = 0;
    const uint8_t* start = in_buf;
    while (true)
    {
        int32_t length;
        for (length = 0; (start + length < in_buf + in_length) && (start[length] != ','); length++)
            ;
        if (length == 0)
            ((uint32_t*)out_buf)[num_codes++] = STAT_EMPTYSTRING;
        else
            ((int64_t*)out_buf)[num_codes++] = str_to_code(start, length, (const StrCode*)table);
        if (start + length >= in_buf + in_length)
            break;
        start += length + 1;
    }
    return num_codes * sizeof(int64_t);
}

// Remove all space and tab characters (known as LWS or linear white space in the RFC)
int32_t norm_remove_lws(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions&, NHttpEventGen&, const void*)
{
    int32_t length = 0;
    for (int32_t k = 0; k < in_length; k++)
    {
        if (!is_sp_tab[in_buf[k]])
            out_buf[length++] = in_buf[k];
    }
    return length;
}

