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
// http2_headers_frame_header.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_headers_frame_header.h"

#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"

#include "http2_dummy_packet.h"
#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_hpack.h"
#include "http2_start_line.h"
#include "http2_stream.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

Http2HeadersFrameHeader::Http2HeadersFrameHeader(const uint8_t* header_buffer,
    const uint32_t header_len, const uint8_t* data_buffer, const uint32_t data_len,
    Http2FlowData* session_data_, HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2HeadersFrame(header_buffer, header_len, data_buffer, data_len, session_data_, source_id_,
        stream_)
{
    if (!process_frame)
        return;

    start_line_generator = Http2StartLine::new_start_line_generator(source_id,
        session_data->events[source_id], session_data->infractions[source_id]);

    // Decode headers
    if (!hpack_decoder->decode_headers((data.start() + hpack_headers_offset), data.length() -
        hpack_headers_offset, decoded_headers, start_line_generator, false))
    {
        session_data->abort_flow[source_id] = true;
        session_data->events[source_id]->create_event(EVENT_MISFORMATTED_HTTP2);
        return;
    }

    // process start line
    if (!start_line_generator->generate_start_line(start_line))
    {
        // FIXIT-E should only be a stream error
        session_data->abort_flow[source_id] = true;
        session_data->events[source_id]->create_event(EVENT_MISFORMATTED_HTTP2);
    }
}

Http2HeadersFrameHeader::~Http2HeadersFrameHeader()
{
    delete start_line_generator;
}

bool Http2HeadersFrameHeader::valid_sequence(Http2Enums::StreamState state)
{
    return (state == Http2Enums::STREAM_EXPECT_HEADERS);
}

void Http2HeadersFrameHeader::analyze_http1()
{
    if (!process_frame)
        return;

    // http_inspect scan() of start line
    {
        uint32_t flush_offset;
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        const uint32_t unused = 0;
        const StreamSplitter::Status start_scan_result =
            session_data->hi_ss[source_id]->scan(&dummy_pkt, start_line.start(),
                start_line.length(), unused, &flush_offset);
        assert(start_scan_result == StreamSplitter::FLUSH);
        UNUSED(start_scan_result);
        assert((int64_t)flush_offset == start_line.length());
    }

    StreamBuffer stream_buf;

    // http_inspect reassemble() of start line
    {
        unsigned copied;
        stream_buf = session_data->hi_ss[source_id]->reassemble(session_data->flow,
            start_line.length(), 0, start_line.start(), start_line.length(), PKT_PDU_TAIL,
            copied);
        assert(stream_buf.data != nullptr);
        assert(copied == (unsigned)start_line.length());
    }

    HttpFlowData* const http_flow =
        session_data->get_current_stream(source_id)->get_hi_flow_data();
    // http_inspect eval() and clear() of start line
    {
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        dummy_pkt.packet_flags = (source_id == SRC_CLIENT) ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
        dummy_pkt.dsize = stream_buf.length;
        dummy_pkt.data = stream_buf.data;
        session_data->hi->eval(&dummy_pkt);
        if (http_flow->get_type_expected(source_id) != HttpEnums::SEC_HEADER)
        {
            *session_data->infractions[source_id] += INF_INVALID_STARTLINE;
            session_data->events[source_id]->create_event(EVENT_INVALID_STARTLINE);
            stream->set_state(source_id, STREAM_ERROR);
            return;
        }
        session_data->hi->clear(&dummy_pkt);
    }

    process_decoded_headers(http_flow);
}

void Http2HeadersFrameHeader::update_stream_state()
{
    if (stream->get_state(source_id) == STREAM_ERROR)
        return;
    if (get_flags() & END_STREAM)
        stream->set_state(source_id, STREAM_COMPLETE);
    else
        stream->set_state(source_id, STREAM_EXPECT_BODY);
}

#ifdef REG_TEST
void Http2HeadersFrameHeader::print_frame(FILE* output)
{
    fprintf(output, "Headers frame\n");
    start_line.print(output, "Decoded start-line");
    Http2HeadersFrame::print_frame(output);
}
#endif
