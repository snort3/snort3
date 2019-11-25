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
// http2_headers_frame.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_headers_frame.h"

#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_hpack.h"
#include "http2_start_line.h"

using namespace HttpCommon;
using namespace Http2Enums;

Http2HeadersFrame::Http2HeadersFrame(const uint8_t* header_buffer, const int32_t header_len,
    const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* session_data,
    HttpCommon::SourceId source_id) : Http2Frame(header_buffer, header_len, data_buffer, data_len,
    session_data, source_id)
{
    uint8_t hpack_headers_offset = 0;

    // Remove stream dependency if present
    if (get_flags() & PRIORITY)
        hpack_headers_offset = 5;

    // Set up the decoding context
    hpack_decoder = &session_data->hpack_decoder[source_id];

    // Allocate stuff
    decoded_headers = new uint8_t[MAX_OCTETS];
    decoded_headers_size = 0;
    
    start_line_generator = Http2StartLine::new_start_line_generator(source_id,
        session_data->events[source_id], session_data->infractions[source_id]);

    // Decode headers
    if (!hpack_decoder->decode_headers((data.start() + hpack_headers_offset), data.length() -
            hpack_headers_offset, decoded_headers, &decoded_headers_size, start_line_generator,
            session_data->events[source_id], session_data->infractions[source_id]))
    {
        session_data->frame_type[source_id] = FT__ABORT;
        error_during_decode = true;
    }
    start_line = hpack_decoder->get_start_line();
    http2_decoded_header = hpack_decoder->get_decoded_headers(decoded_headers);
}

Http2HeadersFrame::~Http2HeadersFrame()
{
    delete start_line;
    delete start_line_generator;
    delete http2_decoded_header;
    delete[] decoded_headers;
}

const Field& Http2HeadersFrame::get_buf(unsigned id)
{
    switch (id)
    {
    case HTTP2_BUFFER_DECODED_HEADER:
        return *http2_decoded_header;
    default:
        return Http2Frame::get_buf(id);
    }
}

#ifdef REG_TEST
void Http2HeadersFrame::print_frame(FILE* output)
{
    fprintf(output, "\nHEADERS frame\n");
    if (error_during_decode)
        fprintf(output, "Error decoding headers.\n");
    if (start_line)
        start_line->print(output, "Decoded start-line");
    http2_decoded_header->print(output, "Decoded header");
    Http2Frame::print_frame(output);
}
#endif
