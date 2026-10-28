//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_head_shared_util.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_head_shared.h"

int32_t HttpMsgHeadShared::get_next_code(const Field& field, int32_t& offset,
    const StrCode table[])
{
    assert(field.length() > 0);
    const uint8_t* start = field.start() + offset;
    int32_t length;
    for (length = 0; (offset+length < field.length()) && (*(start+length) != ','); length++);
    offset += length + 1;
    return str_to_code(start, length, table);
}

// Case insensitive search for the substring "boundary="
bool HttpMsgHeadShared::boundary_present(const Field& field)
{
    assert(field.length() > 0);

    const char* const BOUNDARY = "boundary=";
    const int BOUNDARY_LEN = 9;

    for (int k = 0; k + BOUNDARY_LEN <= field.length(); k++)
    {
        if (strncasecmp(BOUNDARY, (const char*)(field.start() + k), BOUNDARY_LEN) == 0)
            return true;
    }
    return false;
}

static inline bool is_content_type_lws(uint8_t octet)
{
    return octet == ' ' or octet == '\t' or octet == '\r' or octet == '\n';
}

int32_t HttpMsgHeadShared::content_type_media_type(const uint8_t* value, int32_t len,
    int32_t& offset)
{
    offset = 0;
    if (len <= 0)
        return 0;

    while (offset < len and is_content_type_lws(value[offset]))
        offset++;

    // A quoted string can only appear in a parameter, so the first ';' always ends the media type
    const uint8_t* const semicolon = (const uint8_t*)memchr(value + offset, ';', len - offset);
    int32_t end = semicolon ? (int32_t)(semicolon - value) : len;

    while (end > offset and is_content_type_lws(value[end-1]))
        end--;

    return end - offset;
}

bool HttpMsgHeadShared::content_type_is_list(const uint8_t* value, int32_t len)
{
    bool quoted = false;

    for (int32_t k = 0; k < len; k++)
    {
        if (quoted)
        {
            if (value[k] == '\\')
                k++;
            else if (value[k] == '"')
                quoted = false;
        }
        else if (value[k] == '"')
            quoted = true;
        else if (value[k] == ',')
            return true;
    }

    return quoted;
}

bool HttpMsgHeadShared::content_type_matches(const std::string& pattern, const uint8_t* value,
    int32_t len)
{
    if (len <= 0)
        return false;

    const char* const val = (const char*)value;
    const size_t star = pattern.find('*');

    if (star == std::string::npos)
        return (pattern.length() == (size_t)len) and !strncasecmp(pattern.c_str(), val, len);

    const size_t suffix_len = pattern.length() - star - 1;

    if ((size_t)len <= star + suffix_len)
        return false;

    if (strncasecmp(pattern.c_str(), val, star) != 0)
        return false;

    if (strncasecmp(pattern.c_str() + star + 1, val + len - suffix_len, suffix_len) != 0)
        return false;

    for (size_t k = star; k < (size_t)len - suffix_len; k++)
    {
        if (!HttpEnums::token_char[value[k]])
            return false;
    }

    return true;
}

