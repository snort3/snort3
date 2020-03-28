//--------------------------------------------------------------------------
// Copyright (C) 2018-2020 Cisco and/or its affiliates. All rights reserved.
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

#include <cassert>

#include "framework/data_bus.h"
#include "protocols/packet.h"
#include "pub_sub/assistant_gadget_event.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"
#include "service_inspectors/http_inspect/http_test_input.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_stream_splitter.h"
#include "http2_module.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

StreamSplitter::Status Http2StreamSplitter::scan(Packet* pkt, const uint8_t* data, uint32_t length,
    uint32_t, uint32_t* flush_offset)
{
    Profile profile(Http2Module::get_profile_stats());

    // This is the session state information we share with Http2Inspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    Http2FlowData* session_data = (Http2FlowData*)pkt->flow->get_flow_data(Http2FlowData::inspector_id);

    if (session_data == nullptr)
    {
        AssistantGadgetEvent event(pkt, "http");
        DataBus::publish(FLOW_ASSISTANT_GADGET_EVENT, event);
        if (pkt->flow->assistant_gadget == nullptr)
            return HttpStreamSplitter::status_value(StreamSplitter::ABORT, true);
        pkt->flow->set_flow_data(session_data = new Http2FlowData(pkt->flow));
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
            source_id, length, pkt->flow->client_port, pkt->flow->server_port);
        fflush(stdout);
        if (HttpTestManager::get_show_scan())
        {
            Field(length, data).print(stdout, "Scan segment");
        }
    }
#endif

    // General mechanism to abort using scan
    if (session_data->frame_type[source_id] == FT__ABORT)
        return HttpStreamSplitter::status_value(StreamSplitter::ABORT, true);

    const StreamSplitter::Status ret_val =
        implement_scan(session_data, data, length, flush_offset, source_id);

    if (ret_val == StreamSplitter::ABORT)
        session_data->frame_type[source_id] = FT__ABORT;

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

    Http2FlowData* session_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    assert(session_data != nullptr);

#ifdef REG_TEST
    if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
    {
        StreamBuffer http_buf { nullptr, 0 };
        if (!(flags & PKT_PDU_TAIL))
        {
            return http_buf;
        }
        bool tcp_close;
        bool partial_flush;
        uint8_t* test_buffer;
        HttpTestManager::get_test_input_source()->reassemble(&test_buffer, len, source_id,
            tcp_close, partial_flush);
        if (tcp_close)
        {
            finish(flow);
        }
        if (partial_flush)
        {
            init_partial_flush(flow);
        }
        if (test_buffer == nullptr)
        {
            // Source ID does not match test data, no test data was flushed, preparing for a
            // partial flush, preparing for a TCP connection close, or there is no more test
            // data
            return http_buf;
        }
        data = test_buffer;
        total = len;
    }
#endif

    // FIXIT-P: scan uses this to discard bytes until StreamSplitter:DISCARD
    // is implemented
    if (session_data->payload_discard[source_id])
    {
        StreamBuffer frame_buf { nullptr, 0 };
        session_data->payload_discard[source_id] = false;

#ifdef REG_TEST
        if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
        {
            fprintf(HttpTestManager::get_output_file(), "Discarded %u octets\n\n", len);
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

// Eventually we will need to address unexpected connection closes
bool Http2StreamSplitter::finish(Flow* flow)
{
    Profile profile(Http2Module::get_profile_stats());

    Http2FlowData* session_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    // FIXIT-M - this assert has been changed to check for null session data and return false if so
    //           due to lack of reliable feedback to stream that scan has been called...if that is
    //           addressed in stream reassembly rewrite this can be reverted to an assert
    //assert(session_data != nullptr);
    if (!session_data)
        return false;

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
        if (!HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
        {
            printf("Finish from flow data %" PRIu64 " direction %d\n", session_data->seq_num,
                source_id);
            fflush(stdout);
        }
    }
#endif

    // FIXIT-E not supported yet
    return false;
}

bool Http2StreamSplitter::init_partial_flush(Flow* flow)
{
    Profile profile(Http2Module::get_profile_stats());

    if (source_id != SRC_SERVER)
    {
        assert(false);
        return false;
    }

    Http2FlowData* session_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    assert(session_data != nullptr);
    UNUSED(session_data); // just for a little while

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2) &&
        !HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
    {
        printf("HTTP/2 partial flush from flow data %" PRIu64 "\n", session_data->seq_num);
        fflush(stdout);
    }
#endif

    // FIXIT-E not supported yet
    return false;
}

