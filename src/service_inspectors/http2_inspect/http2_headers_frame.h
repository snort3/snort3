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
// http2_headers_frame.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_HEADERS_FRAME_H
#define HTTP2_HEADERS_FRAME_H

#include "http2_frame.h"

class Field;
class Http2HpackDecoder;
class Http2StartLine;
class Http2Frame;

class Http2HeadersFrame : public Http2Frame
{
public:
    ~Http2HeadersFrame() override;
    
    const Field& get_buf(unsigned id) override;

    friend Http2Frame* Http2Frame::new_frame(const uint8_t* header_buffer, const int32_t header_len,
        const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* session_data,
        HttpCommon::SourceId source_id);

#ifdef REG_TEST
    void print_frame(FILE* output) override;
#endif

private:
    Http2HeadersFrame(const uint8_t* header_buffer, const int32_t header_len,
        const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* session_data,
        HttpCommon::SourceId source_id);

    Http2StartLine* start_line_generator = nullptr;
    uint8_t* decoded_headers = nullptr; // working buffer to store decoded headers
    uint32_t decoded_headers_size = 0;
    const Field* http2_decoded_header = nullptr; // finalized headers to be passed to NHI
    const Field* start_line = nullptr;
    bool error_during_decode = false;
    Http2HpackDecoder* hpack_decoder= nullptr;
};
#endif
