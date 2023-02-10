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
// http2_status_line.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_status_line.h"

#include <cstdlib>

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"
#include "http2_flow_data.h"

using namespace HttpCommon;
using namespace Http2Enums;

const char* Http2StatusLine::STATUS_NAME = ":status";

void Http2StatusLine::process_pseudo_header(const Field& name, const Field& value)
{
    if ((name.length() == STATUS_NAME_LENGTH) and
        (memcmp(name.start(), STATUS_NAME, name.length()) == 0) and (status.length() <= 0))
    {
        uint8_t* value_str = new uint8_t[value.length()];
        memcpy(value_str, value.start(), value.length());
        status.set(value.length(), value_str, true);
    }
    else
    {
        *infractions += INF_INVALID_PSEUDO_HEADER;
        events->create_event(EVENT_INVALID_PSEUDO_HEADER);
    }
}

bool Http2StatusLine::generate_start_line(Field& start_line, bool pseudo_headers_complete)
{
    uint32_t bytes_written = 0;

    // Account for one space and trailing crlf
    static const uint8_t NUM_RESPONSE_LINE_EXTRA_CHARS = 3;

    if (status.length() <= 0)
    {
        if (pseudo_headers_complete)
        {
            *infractions += INF_RESPONSE_WITHOUT_STATUS;
            events->create_event(EVENT_RESPONSE_WITHOUT_STATUS);
        }
        return false;
    }

    start_line_length = http_version_length + status.length() + NUM_RESPONSE_LINE_EXTRA_CHARS;
    start_line_buffer = new uint8_t[start_line_length];

    memcpy(start_line_buffer + bytes_written, http_version_string, http_version_length);
    bytes_written += http_version_length;
    memcpy(start_line_buffer + bytes_written, " ", 1);
    bytes_written += 1;
    memcpy(start_line_buffer + bytes_written, status.start(), status.length());
    bytes_written += status.length();
    memcpy(start_line_buffer + bytes_written, "\r\n", 2);
    bytes_written += 2;
    assert(bytes_written == start_line_length);

    start_line.set(start_line_length, start_line_buffer, false);

    return true;
}
