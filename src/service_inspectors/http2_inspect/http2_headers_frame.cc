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
// http2_headers_frame.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_headers_frame.h"

#include "protocols/packet.h"
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

Http2HeadersFrame::Http2HeadersFrame(const uint8_t* header_buffer, const uint32_t header_len,
    const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* session_data_,
    HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2Frame(header_buffer, header_len, data_buffer, data_len, session_data_, source_id_, stream_)
{
    // Remove stream dependency if present
    if (get_flags() & FLAG_PRIORITY)
        hpack_headers_offset = 5;

    // Set up HPACK decoding
    hpack_decoder = &session_data->hpack_decoder[source_id];
}

bool Http2HeadersFrame::in_error_state() const
{
    return stream->get_state(source_id) == STREAM_ERROR;
}

void Http2HeadersFrame::clear()
{
    if (session_data->abort_flow[source_id] || in_error_state())
        return;
    Packet dummy_pkt(false);
    dummy_pkt.flow = session_data->flow;
    session_data->hi->clear(&dummy_pkt);
}

bool Http2HeadersFrame::decode_headers(Http2StartLine* start_line_generator, bool trailers)
{
    const uint32_t encoded_headers_length = (data.length() > hpack_headers_offset) ?
        data.length() - hpack_headers_offset : 0;
    if (!hpack_decoder->decode_headers((data.start() + hpack_headers_offset),
        encoded_headers_length, start_line_generator, trailers))
    {
        if (!(*session_data->infractions[source_id] & INF_TRUNCATED_HEADER_LINE))
        {
            session_data->abort_flow[source_id] = true;
            session_data->events[source_id]->create_event(EVENT_MISFORMATTED_HTTP2);
            session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
            http1_header.set(STAT_PROBLEMATIC);
            hpack_decoder->cleanup();
            return false;
        }
    }
    hpack_decoder->set_decoded_headers(http1_header);
    return true;
}

void Http2HeadersFrame::process_decoded_headers(HttpFlowData* http_flow, SourceId hi_source_id)
{
    if (session_data->abort_flow[source_id] or http1_header.length() < 0)
        return;

    if (http1_header.length() <= 0 and !session_data->is_processing_partial_header())
    {
        // This shouldn't happen because well-formatted empty frames have crlf written to the
        // decoded headers buffer
        assert(false);
        return;
    }

    StreamBuffer stream_buf;

    // http_inspect scan() of headers
    // If we're processing a header truncated immediately after the start line, http1_header will
    // be empty. Don't call scan on the empty buffer because it will create a cutter and the check
    // for this condition in HI::finish() will fail. Truncated headers with non-empty http1_header
    // buffers are still sent to HI::scan().
    if (http1_header.length() > 0)
    {
        uint32_t flush_offset;
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        const uint32_t unused = 0;
        const StreamSplitter::Status header_scan_result =
            session_data->hi_ss[hi_source_id]->scan(&dummy_pkt, http1_header.start(),
            http1_header.length(), unused, &flush_offset);
        assert((session_data->is_processing_partial_header() and
                (header_scan_result == StreamSplitter::SEARCH)) or
            ((!session_data->is_processing_partial_header() and
                (header_scan_result == StreamSplitter::FLUSH))));
        assert(session_data->is_processing_partial_header() or
            ((int64_t)flush_offset == http1_header.length()));
        UNUSED(header_scan_result);
    }

    // If this is a truncated headers frame, call http_inspect finish()
    if (session_data->is_processing_partial_header())
    {
        const bool need_reassemble = session_data->hi_ss[hi_source_id]->finish(session_data->flow);
        assert(need_reassemble);
        UNUSED(need_reassemble);
    }

    // http_inspect reassemble() of headers
    {
        unsigned copied;
        stream_buf = session_data->hi_ss[hi_source_id]->reassemble(session_data->flow,
            http1_header.length(), 0, http1_header.start(), http1_header.length(), PKT_PDU_TAIL,
            copied);
        assert(stream_buf.data != nullptr);
        assert(copied == (unsigned)http1_header.length());
    }

    // http_inspect eval() of headers
    {
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        dummy_pkt.packet_flags = (hi_source_id == SRC_CLIENT) ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
        dummy_pkt.dsize = stream_buf.length;
        dummy_pkt.data = stream_buf.data;
        dummy_pkt.xtradata_mask = 0;
        session_data->hi->eval(&dummy_pkt);
        if (http_flow->get_type_expected(hi_source_id) == SEC_ABORT)
        {
            assert(session_data->is_processing_partial_header());
            stream->set_state(hi_source_id, STREAM_ERROR);
        }
        detection_required = dummy_pkt.is_detection_required();
        xtradata_mask = dummy_pkt.xtradata_mask;
    }
}

const Field& Http2HeadersFrame::get_buf(unsigned id)
{
    switch (id)
    {
    // FIXIT-E need to add a buffer for the decoded start line
    case HTTP2_BUFFER_DECODED_HEADER:
        return http1_header;
    default:
        return Http2Frame::get_buf(id);
    }
}

uint8_t Http2HeadersFrame::get_flags_mask() const
{ return (FLAG_END_STREAM|FLAG_END_HEADERS|FLAG_PADDED|FLAG_PRIORITY); }

#ifdef REG_TEST
void Http2HeadersFrame::print_frame(FILE* output)
{
    http1_header.print(output, "Decoded header");
    Http2Frame::print_frame(output);
}
#endif
