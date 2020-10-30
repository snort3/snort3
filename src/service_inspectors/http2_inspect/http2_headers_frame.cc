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

Http2HeadersFrame::Http2HeadersFrame(const uint8_t* header_buffer, const uint32_t header_len,
    const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* session_data_,
    HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2Frame(header_buffer, header_len, data_buffer, data_len, session_data_, source_id_, stream_)
{
    // FIXIT-E zero length should not be a special case
    if (data.length() <= 0)
    {
        process_frame = false;
        return;
    }

    // Remove stream dependency if present
    if (get_flags() & PRIORITY)
        hpack_headers_offset = 5;

    // Set up HPACK decoding
    hpack_decoder = &session_data->hpack_decoder[source_id];
    decoded_headers = new uint8_t[MAX_OCTETS];
}


Http2HeadersFrame::~Http2HeadersFrame()
{
    delete[] decoded_headers;
}

void Http2HeadersFrame::clear()
{
    if (session_data->abort_flow[source_id] || stream->get_state(source_id) == STREAM_ERROR)
        return;
    Packet dummy_pkt(false);
    dummy_pkt.flow = session_data->flow;
    session_data->hi->clear(&dummy_pkt);
}

void Http2HeadersFrame::process_decoded_headers(HttpFlowData* http_flow, SourceId hi_source_id)
{
    if (session_data->abort_flow[source_id])
        return;

    http1_header = hpack_decoder->get_decoded_headers(decoded_headers);
    StreamBuffer stream_buf;

    // http_inspect scan() of headers
    {
        uint32_t flush_offset;
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        const uint32_t unused = 0;
        const StreamSplitter::Status header_scan_result =
            session_data->hi_ss[hi_source_id]->scan(&dummy_pkt, http1_header.start(),
            http1_header.length(), unused, &flush_offset);
        assert(header_scan_result == StreamSplitter::FLUSH);
        UNUSED(header_scan_result);
        assert((int64_t)flush_offset == http1_header.length());
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
        // Following if condition won't get exercised until finish() (during Headers) is
        // implemented for H2I. Without finish() H2I will only flush complete header blocks. Below
        // ABORT is only possible if tcp connection closes unexpectedly in middle of a header.
        if (http_flow->get_type_expected(hi_source_id) == HttpEnums::SEC_ABORT)
        {
            *session_data->infractions[source_id] += INF_INVALID_HEADER;
            session_data->events[source_id]->create_event(EVENT_INVALID_HEADER);
            stream->set_state(source_id, STREAM_ERROR);
            return;
        }
        detection_required = dummy_pkt.is_detection_required();
        xtradata_mask = dummy_pkt.xtradata_mask;
    }
}

const Field& Http2HeadersFrame::get_buf(unsigned id)
{
    switch (id)
    {
    // FIXIT-M need to add a buffer for the decoded start line
    case HTTP2_BUFFER_DECODED_HEADER:
        return http1_header;
    default:
        return Http2Frame::get_buf(id);
    }
}

#ifdef REG_TEST
void Http2HeadersFrame::print_frame(FILE* output)
{
    http1_header.print(output, "Decoded header");
    Http2Frame::print_frame(output);
}
#endif
