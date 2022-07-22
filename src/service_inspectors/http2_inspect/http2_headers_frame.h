//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
class Http2Stream;
class HttpFlowData;

class Http2HeadersFrame : public Http2Frame
{
public:
    void clear(snort::Packet*) override;

    const Field& get_buf(unsigned id) override;
    bool is_detection_required() const override { return false; }

#ifdef REG_TEST
    void print_frame(FILE* output) override;
#endif

protected:
    Http2HeadersFrame(const uint8_t* header_buffer, const uint32_t header_len,
        const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
        HttpCommon::SourceId src_id, Http2Stream* stream);
    bool decode_headers(Http2StartLine* start_line_generator, bool trailers);
    void process_decoded_headers(HttpFlowData* http_flow, HttpCommon::SourceId hi_source_id, snort::Packet* p);
    uint8_t get_flags_mask() const override;
    virtual bool in_error_state() const;

    Field http1_header;                 // finalized headers to be passed to http_inspect
    Http2HpackDecoder* hpack_decoder;
    uint8_t hpack_headers_offset = 0;
};
#endif
