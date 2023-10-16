//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_str_to_code.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_STR_TO_CODE_H
#define HTTP_STR_TO_CODE_H

#include <cstdint>

struct StrCode
{
    int32_t code;
    const char* name;
};

int32_t str_to_code(const char* text, const StrCode table[]);
int32_t str_to_code(const uint8_t* text, const int32_t text_len, const StrCode table[]);
int32_t substr_to_code(const uint8_t* text, const int32_t text_len, const StrCode table[]);

// Convert the first value in a comma-separated list into a code. consumed is the number of bytes
// used from the list or -1 if there are no more list entries.
int32_t get_code_from_token_list(const uint8_t* token_list, const int32_t text_len,
    int32_t& bytes_consumed, const StrCode table[]);

#endif

