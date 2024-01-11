//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_request_line.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_REQUEST_LINE_H
#define HTTP2_REQUEST_LINE_H

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"
#include "http2_start_line.h"

class Http2RequestLine : public Http2StartLine
{
public:
    Http2RequestLine(Http2EventGen* const evs, Http2Infractions* const infrs) :
        Http2StartLine(evs, infrs) { }
    void process_pseudo_header(const Field& name, const Field& value) override;
    bool generate_start_line(Field& start_line, bool pseudo_headers_complete) override;

private:
    Field method;
    Field path;
    Field scheme;
    Field authority;

    static const char* authority_name;
    static const uint32_t authority_name_length = 10;
    static const char* method_name;
    static const uint32_t method_name_length = 7;
    static const char* path_name;
    static const uint32_t path_name_length = 5;
    static const char* scheme_name;
    static const uint32_t scheme_name_length = 7;

    // Constants used for special checks
    static const char* method_connect;
    static const int32_t connect_length = 7;
    static const char* method_options;
    static const int32_t options_length = 7;
    static const char* scheme_http;
    static const int32_t http_length = 4;
    static const char* scheme_https;
    static const int32_t https_length = 5;

    // Account for two spaces, and trailing crlf
    static const uint8_t num_request_line_extra_chars = 4;
    // absolute form adds '://' between scheme and authority
    static const uint32_t num_absolute_form_extra_chars = 3;
};

#endif
