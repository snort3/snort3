//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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

const char* Http2RequestLine::authority_name = ":authority";
const char* Http2RequestLine::method_name = ":method";
const char* Http2RequestLine::path_name = ":path";
const char* Http2RequestLine::scheme_name = ":scheme";
const char* Http2RequestLine::method_connect = "CONNECT";
const char* Http2RequestLine::method_options = "OPTIONS";
const char* Http2RequestLine::scheme_http = "http";
const char* Http2RequestLine::scheme_https = "https";

void Http2RequestLine::process_pseudo_header(const Field& name, const Field& value)
{
    Field *field;
    if ((name.length() == authority_name_length) and
        (memcmp(name.start(), authority_name, name.length()) == 0) and (authority.length() <= 0))
    {
        field = &authority;
    }
    else if ((name.length() == method_name_length) and
        (memcmp(name.start(), method_name, name.length()) == 0) and (method.length() <= 0))
    {
        field = &method;
    }
    else if ((name.length() == path_name_length) and
        (memcmp(name.start(), path_name, name.length()) == 0) and (path.length() <= 0))
    {
        field = &path;
    }
    else if ((name.length() == scheme_name_length) and
        (memcmp(name.start(), scheme_name, name.length()) == 0) and (scheme.length() <= 0))
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

// Create an HTTP/1.1 request line based on the pseudoheaders present. If there is no method, the
// request is malformed and will not be forwarded on to http_inspect. Requests are generated as
// follows:
// 1. Method followed by one space
// 2. URI:
//      a) If the method is CONNECT, only the authority is used
//      b) If the method is OPTIONS and the path is *, the full URI is '*'
//      c) Otherwise:
//          i) If there is an authority and scheme, the URI will start <scheme>://<authority>
//          ii) Otherwise if either the scheme or authority are there, it is omitted
//      d) If there is a path, it is appended. If the path exists and does not start with '/',
//         prepend a slash to the path.
// 3. One space followed by the string 'HTTP/1.1'
bool Http2RequestLine::generate_start_line(Field& start_line, bool pseudo_headers_complete)
{
    uint32_t bytes_written = 0;

    if (method.length() <= 0)
    {
        if (pseudo_headers_complete)
        {
            *infractions += INF_REQUEST_WITHOUT_METHOD;
            events->create_event(EVENT_REQUEST_WITHOUT_METHOD);
        }
        return false;
    }

    // Compute the length of the URI
    uint32_t uri_len = 0;
    bool use_scheme = false;
    bool use_authority = false;
    bool use_path = false;
    bool add_slash = false;

    // CONNECT requests
    if (method.length() == connect_length and memcmp(method.start(),
        method_connect, method.length()) == 0)
    {
        if (authority.length() <= 0 and pseudo_headers_complete)
        {
            *infractions += INF_CONNECT_WITHOUT_AUTHORITY;
            events->create_event(EVENT_REQUEST_WITHOUT_REQUIRED_FIELD);
        }
        else
        {
            use_authority = true;
            uri_len = authority.length();
        }

        if ( scheme.length() > 0 or path.length() > 0)
        {
            *infractions += INF_CONNECT_WITH_SCHEME_OR_PATH;
            events->create_event(EVENT_CONNECT_WITH_SCHEME_OR_PATH);
        }
    }
    else
    {
        if ((method.length() == options_length and memcmp(method.start(),
                    method_options, method.length()) == 0) and
            (path.length() == 1 and path.start()[0] == '*'))
        {
            // OPTIONS * HTTP/1.1
            use_path = true;
            uri_len = 1;
        }
        else
        {
            if (authority.length() > 0 and scheme.length() > 0)
            {
                uri_len += scheme.length() + authority.length() + num_absolute_form_extra_chars;
                use_scheme = true;
                use_authority = true;
            }
            if (path.length() > 0)
            {
                // If path does not start with slash, prepend slash so http_inspect normalization
                // will be performed
                if (path.start()[0] != '/')
                {
                    add_slash = true;
                    uri_len += 1;
                }
                uri_len += path.length();
                use_path = true;
            }
        }

        // Non-CONNECT requests must have a scheme and http/https schemes must have a path
        if (pseudo_headers_complete)
        {
            const bool is_http = ((scheme.length() == http_length) and
                memcmp(scheme.start(), scheme_http, scheme.length()) == 0) or
                ((scheme.length() == https_length) and
                 memcmp(scheme.start(), scheme_https, scheme.length()) == 0);
            if (scheme.length() <= 0 or (is_http and (path.length() <= 0)))
            {
                *infractions += INF_REQUEST_WITHOUT_REQUIRED_FIELD;
                events->create_event(EVENT_REQUEST_WITHOUT_REQUIRED_FIELD);
            }
        }
    }

    start_line_length = method.length() + uri_len + http_version_length +
        num_request_line_extra_chars;
    start_line_buffer = new uint8_t[start_line_length];

    // Method
    memcpy(start_line_buffer, method.start(), method.length());
    bytes_written += method.length();
    memcpy(start_line_buffer + bytes_written, " ", 1);
    bytes_written += 1;

    // URI
    if (use_scheme)
    {
        assert(scheme.length() > 0);
        assert(use_authority);
        memcpy(start_line_buffer + bytes_written, scheme.start(), scheme.length());
        bytes_written += scheme.length();
        memcpy(start_line_buffer + bytes_written, "://", 3);
        bytes_written += 3;
    }
    if (use_authority)
    {
        assert(authority.length() > 0);
        memcpy(start_line_buffer + bytes_written, authority.start(), authority.length());
        bytes_written += authority.length();
    }
    if (use_path)
    {
        assert(path.length() > 0);
        if (add_slash)
        {
            memcpy(start_line_buffer + bytes_written, "/", 1);
            bytes_written += 1;
        }
        memcpy(start_line_buffer + bytes_written, path.start(), path.length());
        bytes_written += path.length();
    }

    // space plus HTTP/1.1 version string
    memcpy(start_line_buffer + bytes_written, " ", 1);
    bytes_written += 1;
    memcpy(start_line_buffer + bytes_written, http_version_string, http_version_length);
    bytes_written += http_version_length;

    memcpy(start_line_buffer + bytes_written, "\r\n", 2);
    bytes_written += 2;
    assert(bytes_written == start_line_length);

    start_line.set(start_line_length, start_line_buffer, false);

    return true;
}
