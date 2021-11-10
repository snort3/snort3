//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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
// http2_headers_frame_trailer.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_headers_frame_trailer.h"

#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"

#include "http2_dummy_packet.h"
#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_hpack.h"
#include "http2_stream.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

Http2HeadersFrameTrailer::Http2HeadersFrameTrailer(const uint8_t* header_buffer,
    const uint32_t header_len, const uint8_t* data_buffer, const uint32_t data_len,
    Http2FlowData* session_data_, HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2HeadersFrame(header_buffer, header_len, data_buffer, data_len, session_data_, source_id_,
        stream_)
{
    if (!(get_flags() & FLAG_END_STREAM))
    {
        // Trailers without END_STREAM flag set.
        *session_data->infractions[source_id] += INF_TRAILERS_NOT_END;
        session_data->events[source_id]->create_event(EVENT_TRAILERS_NOT_END);
    }
    decode_headers(nullptr, true);
}

bool Http2HeadersFrameTrailer::valid_sequence(Http2Enums::StreamState state)
{
    if ((state == STREAM_EXPECT_BODY) || (state == STREAM_BODY))
        return true;
    if (state == STREAM_COMPLETE)
    {
        *session_data->infractions[source_id] += INF_FRAME_SEQUENCE;
        session_data->events[source_id]->create_event(EVENT_FRAME_SEQUENCE);
    }
    return false;
}

void Http2HeadersFrameTrailer::analyze_http1()
{
    HttpFlowData* const http_flow = stream->get_hi_flow_data();
    assert(http_flow);

    const bool valid_headers = http1_header.length() > 0;
    if (http_flow->get_type_expected(source_id) != HttpEnums::SEC_TRAILER)
    {
        // http_inspect is not yet expecting trailers. Flush empty buffer through scan, reassemble,
        // and eval to prepare http_inspect for trailers.
        assert(http_flow->get_type_expected(source_id) == HttpEnums::SEC_BODY_H2);
        stream->finish_msg_body(source_id, valid_headers, true); // calls http_inspect scan()

        unsigned copied;
        const StreamBuffer stream_buf =
            session_data->hi_ss[source_id]->reassemble(session_data->flow,
            0, 0, nullptr, 0, PKT_PDU_TAIL, copied);
        assert(copied == 0);

        if (stream_buf.data != nullptr)
        {
            Http2DummyPacket dummy_pkt;
            dummy_pkt.flow = session_data->flow;
            dummy_pkt.packet_flags = (source_id == SRC_CLIENT) ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
            dummy_pkt.dsize = stream_buf.length;
            dummy_pkt.data = stream_buf.data;
            session_data->hi->eval(&dummy_pkt);
            assert (!valid_headers || http_flow->get_type_expected(source_id) == HttpEnums::SEC_TRAILER);
            if (http_flow->get_type_expected(source_id) == HttpEnums::SEC_ABORT)
            {
                stream->set_state(source_id, STREAM_ERROR);
                return;
            }
            session_data->hi->clear(&dummy_pkt);
        }
    }

    if (!valid_headers)
    {
        stream->set_state(source_id, STREAM_ERROR);
        return;
    }

    process_decoded_headers(http_flow, source_id);
}

void Http2HeadersFrameTrailer::update_stream_state()
{
    switch (stream->get_state(source_id))
    {
        case STREAM_BODY:
            session_data->concurrent_files -= 1;
            // fallthrough
        case STREAM_EXPECT_BODY:
            stream->set_state(source_id, STREAM_COMPLETE);
            break;
        default:
            break;
    }
}

#ifdef REG_TEST
void Http2HeadersFrameTrailer::print_frame(FILE* output)
{
    fprintf(output, "Trailers frame\n");
    Http2HeadersFrame::print_frame(output);
}

#endif

