//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_cursor_data.h author Brandon Stultz <brastult@cisco.com>

#ifndef HTTP_CURSOR_DATA_H
#define HTTP_CURSOR_DATA_H

#include "framework/cursor.h"

class HttpCursorData : public CursorData
{
public:
    HttpCursorData() : CursorData(id) {}

    static void init()
    { id = CursorData::create_cursor_data_id(); }

    HttpCursorData* clone() override
    { return new HttpCursorData(*this); }

    bool retry()
    {
        return query_index < num_query_params ||
            body_index < num_body_params;
    }

public:
    static unsigned id;
    unsigned num_query_params = 0;
    unsigned num_body_params = 0;
    unsigned query_index = 0;
    unsigned body_index = 0;
};

#endif

