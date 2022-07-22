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
// http2_headers_frame_header.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_headers_frame_header.h"

#include "service_inspectors/http_inspect/http_flow_data.h"

#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_hpack.h"
#include "http2_request_line.h"
#include "http2_status_line.h"
#include "http2_stream.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

Http2HeadersFrameHeader::Http2HeadersFrameHeader(const uint8_t* header_buffer,
    const uint32_t header_len, const uint8_t* data_buffer, const uint32_t data_len,
    Http2FlowData* session_data_, HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2HeadersFrameWithStartline(header_buffer, header_len, data_buffer, data_len, session_data_,
        source_id_, stream_)
{
    if (source_id == SRC_CLIENT)
        start_line_generator = new Http2RequestLine(session_data->events[source_id],
            session_data->infractions[source_id]);
    else
        start_line_generator = new Http2StatusLine(session_data->events[source_id],
            session_data->infractions[source_id]);

    if (decode_headers(start_line_generator, false))
    {
        // process start line
        if (!start_line_generator->generate_start_line(start_line, are_pseudo_headers_complete()))
        {
            stream->set_state(source_id, STREAM_ERROR);
        }
    }
}

bool Http2HeadersFrameHeader::valid_sequence(Http2Enums::StreamState state)
{
    return (state == Http2Enums::STREAM_EXPECT_HEADERS);
}

void Http2HeadersFrameHeader::analyze_http1(Packet* p)
{
    HttpFlowData* http_flow;
    if (!process_start_line(http_flow, source_id, p))
        return;

    // if END_STREAM flag set on headers, tell http_inspect not to expect a message body
    if (get_flags() & FLAG_END_STREAM)
        stream->get_hi_flow_data()->finish_h2_body(source_id, H2_BODY_NO_BODY, false);

    process_decoded_headers(http_flow, source_id, p);
}

void Http2HeadersFrameHeader::update_stream_state()
{
    if (stream->get_state(source_id) == STREAM_ERROR)
        return;
    if (get_flags() & FLAG_END_STREAM)
        stream->set_state(source_id, STREAM_COMPLETE);
    else
        stream->set_state(source_id, STREAM_EXPECT_BODY);
}

#ifdef REG_TEST
void Http2HeadersFrameHeader::print_frame(FILE* output)
{
    fprintf(output, "Headers frame\n");
    Http2HeadersFrameWithStartline::print_frame(output);
}
#endif
