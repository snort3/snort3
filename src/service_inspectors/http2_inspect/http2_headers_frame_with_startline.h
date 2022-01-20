//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// http2_headers_frame_with_startline.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_HEADERS_FRAME_WITH_STARTLINE_H
#define HTTP2_HEADERS_FRAME_WITH_STARTLINE_H

#include "service_inspectors/http_inspect/http_common.h"

#include "http2_enum.h"
#include "http2_frame.h"
#include "http2_headers_frame.h"

class Field;
class Http2Frame;
class Http2Stream;
class HttpFlowData;

class Http2HeadersFrameWithStartline : public Http2HeadersFrame
{
public:
    ~Http2HeadersFrameWithStartline() override;

#ifdef REG_TEST
    void print_frame(FILE* output) override;
#endif

protected:
    Http2HeadersFrameWithStartline(const uint8_t* header_buffer, const uint32_t header_len,
        const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
        HttpCommon::SourceId src_id, Http2Stream* stream_) :
        Http2HeadersFrame(header_buffer, header_len, data_buffer, data_len, ssn_data, src_id,
            stream_) { }
    bool process_start_line(HttpFlowData*& http_flow, HttpCommon::SourceId hi_source_id);
    bool are_pseudo_headers_complete();

    Http2StartLine* start_line_generator = nullptr;
    Field start_line;
};
#endif
