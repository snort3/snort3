//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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

Http2HeadersFrame::Http2HeadersFrame(const uint8_t* header_buffer, const int32_t header_len,
    const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* session_data_,
    HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2Frame(header_buffer, header_len, data_buffer, data_len, session_data_, source_id_, stream_)
{
    // FIXIT-E If the stream state is not IDLE, we've already received the headers. Trailers are
    // not yet being processed
    if (stream->get_state(source_id) >= STATE_OPEN)
    {
        trailer = true;
        return;
    }

    // No need to process an empty headers frame
    if (data.length() <= 0)
        return;

    uint8_t hpack_headers_offset = 0;

    // Remove stream dependency if present
    if (get_flags() & PRIORITY)
        hpack_headers_offset = 5;

    // Set up the decoding context
    Http2HpackDecoder& hpack_decoder = session_data->hpack_decoder[source_id];

    // Allocate stuff
    decoded_headers = new uint8_t[MAX_OCTETS];

    start_line_generator = Http2StartLine::new_start_line_generator(source_id,
        session_data->events[source_id], session_data->infractions[source_id]);

    // Decode headers
    if (!hpack_decoder.decode_headers((data.start() + hpack_headers_offset), data.length() -
        hpack_headers_offset, decoded_headers, start_line_generator))
    {
        session_data->frame_type[source_id] = FT__ABORT;
        error_during_decode = true;
    }
    start_line = hpack_decoder.get_start_line();
    http1_header = hpack_decoder.get_decoded_headers(decoded_headers);

    if (error_during_decode)
        return;

    // http_inspect scan() of start line
    {
        uint32_t flush_offset;
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        const uint32_t unused = 0;
        const StreamSplitter::Status start_scan_result =
            session_data->hi_ss[source_id]->scan(&dummy_pkt, start_line->start(),
            start_line->length(), unused, &flush_offset);
        assert(start_scan_result == StreamSplitter::FLUSH);
        UNUSED(start_scan_result);
        assert((int64_t)flush_offset == start_line->length());
    }

    StreamBuffer stream_buf;
    // http_inspect reassemble() of start line
    {
        unsigned copied;
        stream_buf = session_data->hi_ss[source_id]->reassemble(session_data->flow,
            start_line->length(), 0, start_line->start(), start_line->length(), PKT_PDU_TAIL,
            copied);
        assert(stream_buf.data != nullptr);
        assert(copied == (unsigned)start_line->length());
    }

    HttpFlowData* http_flow = session_data->get_current_stream(source_id)->get_hi_flow_data();
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
            hi_abort = true;
            return;
        }
        session_data->hi->clear(&dummy_pkt);
    }

    // http_inspect scan() of headers
    {
        uint32_t flush_offset;
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        const uint32_t unused = 0;
        const StreamSplitter::Status header_scan_result =
            session_data->hi_ss[source_id]->scan(&dummy_pkt, http1_header->start(),
            http1_header->length(), unused, &flush_offset);
        assert(header_scan_result == StreamSplitter::FLUSH);
        UNUSED(header_scan_result);
        assert((int64_t)flush_offset == http1_header->length());
    }

    // http_inspect reassemble() of headers
    {
        unsigned copied;
        stream_buf = session_data->hi_ss[source_id]->reassemble(session_data->flow,
            http1_header->length(), 0, http1_header->start(), http1_header->length(), PKT_PDU_TAIL,
            copied);
        assert(stream_buf.data != nullptr);
        assert(copied == (unsigned)http1_header->length());
    }

    // http_inspect eval() of headers
    {
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        dummy_pkt.packet_flags = (source_id == SRC_CLIENT) ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
        dummy_pkt.dsize = stream_buf.length;
        dummy_pkt.data = stream_buf.data;
        dummy_pkt.xtradata_mask = 0;
        session_data->hi->eval(&dummy_pkt);
        //Following if condition won't get exercised until finish() is
        //implemented for H2I. Without finish() H2I will only flush
        //complete header blocks. Below ABORT is only possible if
        //tcp connection closes unexpectedly in middle of a header.
        if (http_flow->get_type_expected(source_id) == HttpEnums::SEC_ABORT)
        {
            *session_data->infractions[source_id] += INF_INVALID_HEADER;
            session_data->events[source_id]->create_event(EVENT_INVALID_HEADER);
            hi_abort = true;
            return;
        }
        detection_required = dummy_pkt.is_detection_required();
        xtradata_mask = dummy_pkt.xtradata_mask;
    }
}

Http2HeadersFrame::~Http2HeadersFrame()
{
    delete start_line;
    delete start_line_generator;
    delete http1_header;
    delete[] decoded_headers;
}

void Http2HeadersFrame::clear()
{
    if (error_during_decode || hi_abort)
        return;
    Packet dummy_pkt(false);
    dummy_pkt.flow = session_data->flow;
    session_data->hi->clear(&dummy_pkt);
}

const Field& Http2HeadersFrame::get_buf(unsigned id)
{
    switch (id)
    {
    // FIXIT-M need to add a buffer for the decoded start line
    case HTTP2_BUFFER_DECODED_HEADER:
        return *http1_header;
    default:
        return Http2Frame::get_buf(id);
    }
}

void Http2HeadersFrame::update_stream_state()
{
    switch (stream->get_state(source_id))
    {
        case STATE_IDLE:
            if (get_flags() & END_STREAM)
                stream->set_state(source_id, STATE_CLOSED);
            else
                stream->set_state(source_id, STATE_OPEN);
            break;
        case STATE_OPEN:
            // fallthrough
        case STATE_OPEN_DATA:
            if (get_flags() & END_STREAM)
            {
                if (stream->get_state(source_id) == STATE_OPEN_DATA)
                    session_data->concurrent_files -= 1;
                stream->set_state(source_id, STATE_CLOSED);
            }
            else
            {
                // Headers frame without end_stream flag set after initial Headers frame
                *session_data->infractions[source_id] += INF_FRAME_SEQUENCE;
                session_data->events[source_id]->create_event(EVENT_FRAME_SEQUENCE);
            }
            break;
        case STATE_CLOSED:
            // Trailers in closed state
            *session_data->infractions[source_id] += INF_TRAILERS_AFTER_END_STREAM;
            session_data->events[source_id]->create_event(EVENT_FRAME_SEQUENCE);
            break;
    }
}


#ifdef REG_TEST
void Http2HeadersFrame::print_frame(FILE* output)
{
    if (!trailer)
        fprintf(output, "Headers frame\n");
    else
        fprintf(output, "Trailing Headers frame\n");
    if (error_during_decode)
        fprintf(output, "Error decoding headers.\n");
    if (start_line)
        start_line->print(output, "Decoded start-line");
    if (http1_header)
        http1_header->print(output, "Decoded header");
    Http2Frame::print_frame(output);
}
#endif
