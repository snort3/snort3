//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

