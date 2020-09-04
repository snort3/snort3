//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// http2_headers_frame_header.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_HEADERS_FRAME_HEADER_H
#define HTTP2_HEADERS_FRAME_HEADER_H

#include "http2_frame.h"
#include "http2_headers_frame.h"

class Http2StartLine;

class Http2HeadersFrameHeader : public Http2HeadersFrame
{
public:
    ~Http2HeadersFrameHeader();
    
    friend Http2Frame* Http2Frame::new_frame(const uint8_t*, const int32_t, const uint8_t*,
        const int32_t, Http2FlowData*, HttpCommon::SourceId, Http2Stream* stream);

#ifdef REG_TEST
    void print_frame(FILE* output) override;
#endif

private:
    Http2HeadersFrameHeader(const uint8_t* header_buffer, const int32_t header_len,
        const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* ssn_data,
        HttpCommon::SourceId src_id, Http2Stream* stream);

    Http2StartLine* start_line_generator = nullptr;
    const Field* start_line = nullptr;
};
#endif
