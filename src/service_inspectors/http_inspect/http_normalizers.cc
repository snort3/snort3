//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_normalizers.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_normalizers.h"

#include <cstring>

using namespace HttpEnums;

// Collection of stock normalization functions. This will probably grow throughout the life of the
// software. New functions must follow the standard signature. The void* at the end is for any
// special configuration data the function requires.

int32_t norm_to_lower(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    HttpInfractions*, HttpEventGen*)
{
    for (int32_t k=0; k < in_length; k++)
    {
        // FIXIT-P tolower() might perform better but must be sure <locale> cannot be pulled in
        out_buf[k] = ((in_buf[k] < 'A') || (in_buf[k] > 'Z')) ? in_buf[k] : in_buf[k] - ('A' -
            'a');
    }
    return in_length;
}

// Remove all space and tab characters (known as LWS or linear white space in the RFC)
int32_t norm_remove_lws(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    HttpInfractions*, HttpEventGen*)
{
    int32_t length = 0;
    for (int32_t k = 0; k < in_length; k++)
    {
        if (!is_sp_tab[in_buf[k]])
            out_buf[length++] = in_buf[k];
    }
    return length;
}

int32_t norm_remove_quotes_lws(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    HttpInfractions*, HttpEventGen*)
{
    int32_t length = 0;
    for (int32_t k=0; k < in_length; k++)
    {
        if (!is_sp_tab_quote_dquote[in_buf[k]])
            out_buf[length++] = in_buf[k];
    }
    return length;
}

// Other header-value processing functions (not using the standard normalization signature)
// Convert a decimal field such as Content-Length to an integer. If multiple comma-separated
// values use the first one.
int64_t norm_decimal_integer(const Field& input)
{
    assert(input.length() > 0);
    // Limited to 18 decimal digits, not including leading zeros, to fit comfortably into int64_t
    int64_t total = 0;
    int non_leading_zeros = 0;
    int32_t k=0;
    do
    {
        int value = input.start()[k] - '0';
        if ((non_leading_zeros > 0) || (value != 0))
            non_leading_zeros++;
        if (non_leading_zeros > 18)
            return STAT_PROBLEMATIC;
        if ((value < 0) || (value > 9))
            return STAT_PROBLEMATIC;
        total = total*10 + value;
    }
    while ((++k < input.length()) && (input.start()[k] != ','));
    return total;
}

void get_last_token(const Field& input, Field& last_token, char ichar)
{
    assert(input.length() > 0);
    const uint8_t* last_start = input.start() + input.length() - 1;
    for (; (last_start >= input.start()) && (*last_start != ichar); last_start--);
    last_start++;
    last_token.set(input.length() - (last_start - input.start()), last_start);
}

