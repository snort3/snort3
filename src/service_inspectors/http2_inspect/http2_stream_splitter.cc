//--------------------------------------------------------------------------
// Copyright (C) 2018-2022 Cisco and/or its affiliates. All rights reserved.
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
// http2_stream_splitter.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_stream_splitter.h"

#include <cassert>

#include "framework/data_bus.h"
#include "protocols/packet.h"
#include "pub_sub/assistant_gadget_event.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"
#include "service_inspectors/http_inspect/http_test_input.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_module.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

StreamSplitter::Status Http2StreamSplitter::scan(Packet* pkt, const uint8_t* data, uint32_t length,
    uint32_t, uint32_t* flush_offset)
{
    Profile profile(Http2Module::get_profile_stats());

    Flow* const flow = pkt->flow;
    if (flow->session_state & STREAM_STATE_MIDSTREAM)
        return StreamSplitter::ABORT;

    // This is the session state information we share with Http2Inspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    Http2FlowData* session_data =
        (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);

    if (session_data == nullptr)
    {
        AssistantGadgetEvent event(pkt, "http");
        DataBus::publish(FLOW_ASSISTANT_GADGET_EVENT, event, flow);
        if (flow->assistant_gadget == nullptr)
        {
            // http_inspect is not configured
            return HttpStreamSplitter::status_value(StreamSplitter::ABORT, true);
        }
        flow->set_flow_data(session_data = new Http2FlowData(flow));
        Http2Module::increment_peg_counts(PEG_FLOW);
    }

#ifdef REG_TEST
    uint32_t dummy_flush_offset;

    if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
    {
        // This block substitutes a completely new data buffer supplied by the test tool in place
        // of the "real" data. It also rewrites the buffer length.
        *flush_offset = length;
        uint8_t* test_data = nullptr;
        HttpTestManager::get_test_input_source()->scan(test_data, length, source_id,
            session_data->seq_num);
        if (length == 0)
            return StreamSplitter::FLUSH;
        data = test_data;
        flush_offset = &dummy_flush_offset;
    }
    else if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
        printf("HTTP/2 scan from flow data %" PRIu64
            " direction %d length %u client port %hu server port %hu\n", session_data->seq_num,
            source_id, length, flow->client_port, flow->server_port);
        fflush(stdout);
        if (HttpTestManager::get_show_scan())
        {
            Field(length, data).print(stdout, "Scan segment");
        }
    }
#endif

    // General mechanism to abort using scan
    if (session_data->abort_flow[source_id])
        return HttpStreamSplitter::status_value(StreamSplitter::ABORT, true);

    const StreamSplitter::Status ret_val =
        implement_scan(session_data, data, length, flush_offset, source_id);

    session_data->bytes_scanned[source_id] += (ret_val == StreamSplitter::FLUSH)?
        *flush_offset : length;

    if (ret_val == StreamSplitter::ABORT)
        session_data->abort_flow[source_id] = true;

#ifdef REG_TEST
    if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
        if (ret_val == StreamSplitter::FLUSH)
            HttpTestManager::get_test_input_source()->flush(*flush_offset);
#endif

    return HttpStreamSplitter::status_value(ret_val, true);
}

// Generic reassemble() copies the inputs unchanged into a static buffer
const StreamBuffer Http2StreamSplitter::reassemble(Flow* flow, unsigned total, unsigned offset,
    const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied)
{
    Profile profile(Http2Module::get_profile_stats());

    copied = len;
    StreamBuffer frame_buf { nullptr, 0 };

    Http2FlowData* session_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    if (session_data == nullptr)
    {
        assert(false);
        return frame_buf;
    }

#ifdef REG_TEST
    if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
    {
        if (!(flags & PKT_PDU_TAIL))
        {
            return frame_buf;
        }
        bool tcp_close;
        uint8_t* test_buffer;
        HttpTestManager::get_test_input_source()->reassemble(&test_buffer, len, total, offset,
            flags, source_id, tcp_close);
        if (tcp_close)
        {
            finish(flow);
        }
        if (test_buffer == nullptr)
        {
            // Source ID does not match test data, no test data was flushed, preparing for a TCP
            // connection close, or there is no more test data
            return frame_buf;
        }
        data = test_buffer;
    }
#endif

    if (session_data->abort_flow[source_id])
    {
        assert(false);
        return frame_buf;
    }

    // FIXIT-P: scan uses this to discard bytes until StreamSplitter:DISCARD
    // is implemented
    if (session_data->payload_discard[source_id])
    {
        if (flags & PKT_PDU_TAIL)
        {
            session_data->payload_discard[source_id] = false;
            session_data->bytes_scanned[source_id] = 0;
        }

#ifdef REG_TEST
        if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
        {
            fprintf(HttpTestManager::get_output_file(), "HTTP/2 discarded %u octets\n\n", len);
            fflush(HttpTestManager::get_output_file());
        }
#endif
        return frame_buf;
    }

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
        if (!HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
        {
            printf("HTTP/2 reassemble from flow data %" PRIu64
                " direction %d total %u length %u\n", session_data->seq_num, source_id,
                total, len);
            fflush(stdout);
        }
    }
#endif

    return implement_reassemble(session_data, total, offset, data, len, flags, source_id);
}

bool Http2StreamSplitter::finish(Flow* flow)
{
    Profile profile(Http2Module::get_profile_stats());

    Http2FlowData* session_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    if (!session_data)
    {
        // assert(false); // FIXIT-M this should not be possible but currently it may be
        return false;
    }
    if (session_data->abort_flow[source_id])
        return false;

    if (session_data->tcp_close[source_id])
    {
        // assert(false); // FIXIT-M this should not happen but it does
        session_data->abort_flow[source_id] = true;
        return false;
    }
    session_data->tcp_close[source_id] = true;

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
        {
            if (!HttpTestManager::get_test_input_source()->finish())
                return false;
        }
        else
        {
            printf("HTTP/2 finish from flow data %" PRIu64 " direction %d\n",
                session_data->seq_num, source_id);
            fflush(stdout);
        }
    }
#endif

    bool need_reassemble = false;

    // First check if there is a partial header that needs to be processed. If we have a partial
    // trailer don't call finish on that stream below
    if (((session_data->frame_type[source_id] == FT_HEADERS) or
            (session_data->frame_type[source_id] == FT_PUSH_PROMISE)) and
        ((session_data->scan_remaining_frame_octets[source_id] > 0) or
            (session_data->continuation_expected[source_id])))
    {
        session_data->processing_partial_header = true;
        need_reassemble = true;
#ifdef REG_TEST
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
            HttpTestManager::get_test_input_source()->flush(0);
#endif
    }

    // Loop through all nonzero streams with open message bodies and call NHI finish()
    for (const Http2Stream* stream : session_data->streams)
    {
        if ((stream->get_stream_id() == 0)                            ||
            (stream->get_state(source_id) >= STREAM_COMPLETE)         ||
            (stream->get_hi_flow_data() == nullptr)                   ||
            (stream->get_hi_flow_data()->get_type_expected(source_id)
                != HttpEnums::SEC_BODY_H2)                            ||
            (session_data->processing_partial_header &&
                (stream->get_stream_id() == session_data->current_stream[source_id])))
        {
            continue;
        }

        session_data->stream_in_hi = stream->get_stream_id();
        if (session_data->hi_ss[source_id]->finish(flow))
        {
            assert(stream->get_stream_id() == session_data->current_stream[source_id]);
            need_reassemble = true;
#ifdef REG_TEST
            if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
                HttpTestManager::get_test_input_source()->flush(0);
#endif
        }
        session_data->stream_in_hi = NO_STREAM_ID;
    }

    return need_reassemble;
}

