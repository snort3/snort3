//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// http2_start_line.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_START_LINE_H
#define HTTP2_START_LINE_H

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"

class Http2FlowData;

class Http2StartLine
{
public:
    Http2StartLine(Http2FlowData* _session_data, HttpCommon::SourceId _source_id);
    virtual ~Http2StartLine() = default;

    friend class Http2Hpack;

    const Field& get_start_line() { return start_line; }
    virtual bool process_pseudo_header_name(const uint64_t index) = 0;
    virtual bool process_pseudo_header_name(const uint8_t* const& name, uint32_t length) = 0;
    virtual void process_pseudo_header_value(const uint8_t* const& value, const uint32_t length) = 0;
    bool finalize();
    bool is_finalized() { return finalized; }
    uint32_t get_start_line_length() { return start_line_length; }
    bool is_pseudo_value() { return value_coming != Http2Enums::HEADER_NONE; }
    bool is_pseudo_name(const char* const& name) { return name[0] == ':'; }

protected:
    bool process_pseudo_header_precheck();
    virtual bool generate_start_line() = 0;

    Field start_line;
    Http2FlowData* session_data;
    HttpCommon::SourceId source_id;
    bool finalized = false;
    uint32_t start_line_length = 0;
    Http2Enums::PseudoHeaders value_coming = Http2Enums::HEADER_NONE;

    // Version string is HTTP/1.1
    static const char* http_version_string;
    static const uint8_t http_version_length = 8;
    // Account for two spaces, and trailing crlf
    static const uint8_t start_line_extra_chars = 4;
};

#endif
