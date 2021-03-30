//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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
// http2_request_line.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_request_line.h"

#include <cstdlib>
#include <cstring>

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"
#include "http2_flow_data.h"

using namespace HttpCommon;
using namespace Http2Enums;

const char* Http2RequestLine::AUTHORITY_NAME = ":authority";
const char* Http2RequestLine::METHOD_NAME = ":method";
const char* Http2RequestLine::PATH_NAME = ":path";
const char* Http2RequestLine::SCHEME_NAME = ":scheme";
const char* Http2RequestLine::OPTIONS = "OPTIONS";
const char* Http2RequestLine::CONNECT = "CONNECT";

void Http2RequestLine::process_pseudo_header(const Field& name, const Field& value)
{
    Field *field;
    if ((name.length() == AUTHORITY_NAME_LENGTH) and
        (memcmp(name.start(), AUTHORITY_NAME, name.length()) == 0) and (authority.length() <= 0))
    {
        field = &authority;
    }
    else if ((name.length() == METHOD_NAME_LENGTH) and
        (memcmp(name.start(), METHOD_NAME, name.length()) == 0) and (method.length() <= 0))
    {
        field = &method;
    }
    else if ((name.length() == PATH_NAME_LENGTH) and
        (memcmp(name.start(), PATH_NAME, name.length()) == 0) and (path.length() <= 0))
    {
        field = &path;
    }
    else if ((name.length() == SCHEME_NAME_LENGTH) and
        (memcmp(name.start(), SCHEME_NAME, name.length()) == 0) and (scheme.length() <= 0))
    {
        field = &scheme;
    }
    else
    {
        *infractions += INF_INVALID_PSEUDO_HEADER;
        events->create_event(EVENT_INVALID_PSEUDO_HEADER);
        return;
    }
    uint8_t* value_str = new uint8_t[value.length()];
    memcpy(value_str, value.start(), value.length());
    field->set(value.length(), value_str, true);
}

// Select the appropriate URI form based on the provided pseudo-headers and generate the start line
bool Http2RequestLine::generate_start_line(Field& start_line, bool pseudo_headers_complete)
{
    uint32_t bytes_written = 0;

    if (method.length() <= 0)
    {
        if (pseudo_headers_complete)
        {
            *infractions += INF_REQUEST_WITHOUT_METHOD;
            events->create_event(EVENT_REQUEST_WITHOUT_REQUIRED_FIELD);
        }
        return false;
    }

    // Asterisk form - used for OPTIONS requests
    if (path.length() > 0 and path.start()[0] == '*')
    {
        start_line_length = method.length() + path.length() + http_version_length +
            NUM_REQUEST_LINE_EXTRA_CHARS;
        start_line_buffer = new uint8_t[start_line_length];

        memcpy(start_line_buffer, method.start(), method.length());
        bytes_written += method.length();
        memcpy(start_line_buffer + bytes_written, " ", 1);
        bytes_written += 1;
        memcpy(start_line_buffer + bytes_written, path.start(), path.length());
        bytes_written += path.length();
        memcpy(start_line_buffer + bytes_written, " ", 1);
        bytes_written += 1;
        memcpy(start_line_buffer + bytes_written, http_version_string, http_version_length);
        bytes_written += http_version_length;
    }
    // Authority form - used for CONNECT requests
    else if (method.length() == CONNECT_LENGTH and memcmp(method.start(),
        CONNECT, method.length()) == 0)
    {
        // Must have an authority
        // FIXIT-L May want to be more lenient than RFC on generating start line
        if (authority.length() <= 0)
        {
            if (pseudo_headers_complete)
            {
                *infractions += INF_CONNECT_WITHOUT_AUTHORITY;
                events->create_event(EVENT_REQUEST_WITHOUT_REQUIRED_FIELD);
            }
            return false;
        }
        // Should not have a scheme or path
        if ( scheme.length() > 0 or path.length() > 0)
        {
            *infractions += INF_CONNECT_WITH_SCHEME_OR_PATH;
            events->create_event(EVENT_CONNECT_WITH_SCHEME_OR_PATH);
        }
        start_line_length = method.length() + authority.length() + http_version_length +
            NUM_REQUEST_LINE_EXTRA_CHARS;
        start_line_buffer = new uint8_t[start_line_length];

        memcpy(start_line_buffer, method.start(), method.length());
        bytes_written += method.length();
        memcpy(start_line_buffer + bytes_written, " ", 1);
        bytes_written += 1;
        memcpy(start_line_buffer + bytes_written, authority.start(), authority.length());
        bytes_written += authority.length();
        memcpy(start_line_buffer + bytes_written, " ", 1);
        bytes_written += 1;
        memcpy(start_line_buffer + bytes_written, http_version_string, http_version_length);
        bytes_written += http_version_length;
    }
    // HTTP/2 requests with URIs in absolute or origin form must have a method, scheme, and length
    else if (scheme.length() > 0 and path.length() > 0)
    {
        // If there is an authority, the URI is in absolute form
        if (authority.length() > 0)
        {
            start_line_length = method.length() + scheme.length() + authority.length() +
                path.length() + http_version_length + NUM_REQUEST_LINE_EXTRA_CHARS +
                NUM_ABSOLUTE_FORM_EXTRA_CHARS;
            start_line_buffer = new uint8_t[start_line_length];

            memcpy(start_line_buffer, method.start(), method.length());
            bytes_written += method.length();
            memcpy(start_line_buffer + bytes_written, " ", 1);
            bytes_written += 1;
            memcpy(start_line_buffer + bytes_written, scheme.start(), scheme.length());
            bytes_written += scheme.length();
            memcpy(start_line_buffer + bytes_written, "://", 3);
            bytes_written += 3;
            memcpy(start_line_buffer + bytes_written, authority.start(), authority.length());
            bytes_written += authority.length();
            memcpy(start_line_buffer + bytes_written, path.start(), path.length());
            bytes_written += path.length();
            memcpy(start_line_buffer + bytes_written, " ", 1);
            bytes_written += 1;
            memcpy(start_line_buffer + bytes_written, http_version_string, http_version_length);
            bytes_written += http_version_length;
        }
        // If there is no authority, the URI is in origin form
        else
        {
            start_line_length = method.length() + path.length() + http_version_length +
                NUM_REQUEST_LINE_EXTRA_CHARS;
            start_line_buffer = new uint8_t[start_line_length];

            memcpy(start_line_buffer, method.start(), method.length());
            bytes_written += method.length();
            memcpy(start_line_buffer + bytes_written, " ", 1);
            bytes_written += 1;
            memcpy(start_line_buffer + bytes_written, path.start(), path.length());
            bytes_written += path.length();
            memcpy(start_line_buffer + bytes_written, " ", 1);
            bytes_written += 1;
            memcpy(start_line_buffer + bytes_written, http_version_string, http_version_length);
            bytes_written += http_version_length;
        }
    }
    else
    {
        // FIXIT-E May want to be more lenient than RFC on generating start line
        if (pseudo_headers_complete)
        {
            *infractions += INF_REQUEST_WITHOUT_REQUIRED_FIELD;
            events->create_event(EVENT_REQUEST_WITHOUT_REQUIRED_FIELD);
        }
        return false;
    }

    memcpy(start_line_buffer + bytes_written, "\r\n", 2);
    bytes_written += 2;
    assert(bytes_written == start_line_length);

    start_line.set(start_line_length, start_line_buffer, false);

    return true;
}
