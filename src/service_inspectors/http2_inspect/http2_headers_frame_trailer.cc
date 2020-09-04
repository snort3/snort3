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

Http2HeadersFrameTrailer::Http2HeadersFrameTrailer(const uint8_t* header_buffer, const int32_t header_len,
    const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* session_data_,
    HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2HeadersFrame(header_buffer, header_len, data_buffer, data_len, session_data_, source_id_,
        stream_)
{
    if (!process_frame)
        return;

    StreamBuffer stream_buf;
    HttpFlowData* http_flow;

    http_flow = session_data->get_current_stream(source_id)->get_hi_flow_data();
    assert(http_flow);
    if (http_flow->get_type_expected(source_id) != HttpEnums::SEC_TRAILER)
    {
        // If there was no unflushed data on this stream when the trailers arrived, http_inspect
        // will not yet be expecting trailers. Flush empty buffer through scan, reassemble, and
        // eval to prepare http_inspect for trailers.
        assert(http_flow->get_type_expected(source_id) == HttpEnums::SEC_BODY_H2);
        stream->finish_msg_body(source_id, true, true); // calls http_inspect scan()

        unsigned copied;
        stream_buf = session_data->hi_ss[source_id]->reassemble(session_data->flow,
            0, 0, nullptr, 0, PKT_PDU_TAIL, copied);
        assert(stream_buf.data != nullptr);
        assert(copied == 0);

        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        dummy_pkt.packet_flags = (source_id == SRC_CLIENT) ? PKT_FROM_CLIENT : PKT_FROM_SERVER;
        dummy_pkt.dsize = stream_buf.length;
        dummy_pkt.data = stream_buf.data;
        session_data->hi->eval(&dummy_pkt);
        assert (http_flow->get_type_expected(source_id) == HttpEnums::SEC_TRAILER);
        if (http_flow->get_type_expected(source_id) == HttpEnums::SEC_ABORT)
        {
            hi_abort = true;
            return;
        }
        session_data->hi->clear(&dummy_pkt);
    }

    // Decode headers
    if (!hpack_decoder->decode_headers((data.start() + hpack_headers_offset), data.length() -
        hpack_headers_offset, decoded_headers, nullptr, true))
    {
        session_data->frame_type[source_id] = FT__ABORT;
        error_during_decode = true;
    }

    process_decoded_headers(http_flow);
}

#ifdef REG_TEST
void Http2HeadersFrameTrailer::print_frame(FILE* output)
{
    fprintf(output, "Trailers frame\n");
    Http2HeadersFrame::print_frame(output);

}
#endif
