//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
// http_stream_splitter_scan.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_io/active.h"

#include "http_common.h"
#include "http_cutter.h"
#include "http_enum.h"
#include "http_inspect.h"
#include "http_module.h"
#include "http_stream_splitter.h"
#include "http_test_input.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

// Convenience function. All housekeeping that must be done before we can return FLUSH to stream.
void HttpStreamSplitter::prepare_flush(HttpFlowData* session_data, uint32_t* flush_offset,
    SectionType section_type, uint32_t num_flushed, uint32_t num_excess, int32_t num_head_lines,
    bool is_broken_chunk, uint32_t num_good_chunks, uint32_t octets_seen) const
{
    session_data->section_type[source_id] = section_type;
    session_data->num_excess[source_id] = num_excess;
    session_data->num_head_lines[source_id] = num_head_lines;
    session_data->is_broken_chunk[source_id] = is_broken_chunk;
    session_data->num_good_chunks[source_id] = num_good_chunks;
    session_data->octets_expected[source_id] = octets_seen + num_flushed;

    if (flush_offset != nullptr)
    {
#ifdef REG_TEST
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
        {
            HttpTestManager::get_test_input_source()->flush(num_flushed);
        }
        else
#endif
        *flush_offset = num_flushed;
    }
}

HttpCutter* HttpStreamSplitter::get_cutter(SectionType type,
    HttpFlowData* session_data) const
{
    switch (type)
    {
    case SEC_REQUEST:
        return (HttpCutter*)new HttpRequestCutter;
    case SEC_STATUS:
        return (HttpCutter*)new HttpStatusCutter;
    case SEC_HEADER:
    case SEC_TRAILER:
        return (HttpCutter*)new HttpHeaderCutter;
    case SEC_BODY_CL:
        return (HttpCutter*)new HttpBodyClCutter(
            session_data->data_length[source_id],
            session_data->accelerated_blocking[source_id],
            my_inspector->script_finder,
            session_data->compression[source_id]);
    case SEC_BODY_CHUNK:
        return (HttpCutter*)new HttpBodyChunkCutter(
            my_inspector->params->maximum_chunk_length,
            session_data->accelerated_blocking[source_id],
            my_inspector->script_finder,
            session_data->compression[source_id]);
    case SEC_BODY_OLD:
        return (HttpCutter*)new HttpBodyOldCutter(
            session_data->accelerated_blocking[source_id],
            my_inspector->script_finder,
            session_data->compression[source_id]);
    case SEC_BODY_H2:
        return (HttpCutter*)new HttpBodyH2Cutter(
            session_data->data_length[source_id],
            session_data->accelerated_blocking[source_id],
            my_inspector->script_finder,
            session_data->compression[source_id]);
    default:
        assert(false);
        return nullptr;
    }
}

// FIXIT-M this function is shared code that needs to get rolled up into a utility that supports
// HI, H2I, and future service inspectors
StreamSplitter::Status HttpStreamSplitter::status_value(StreamSplitter::Status ret_val, bool http2)
{
    UNUSED(http2);
#ifdef REG_TEST
    const HttpTestManager::INPUT_TYPE type =
        http2 ? HttpTestManager::IN_HTTP2 : HttpTestManager::IN_HTTP;
    if (HttpTestManager::use_test_output(type))
    {
        fprintf(HttpTestManager::get_output_file(), "%sscan() returning status %d\n",
            http2 ? "HTTP/2 ": "", ret_val);
        fflush(HttpTestManager::get_output_file());
    }
    if (HttpTestManager::use_test_input(type))
    {
        return StreamSplitter::FLUSH;
    }
#endif
    return ret_val;
}

StreamSplitter::Status HttpStreamSplitter::scan(Packet* pkt, const uint8_t* data, uint32_t length,
    uint32_t, uint32_t* flush_offset)
{
    Profile profile(HttpModule::get_profile_stats());

    Flow* const flow = pkt->flow;

    // This is the session state information we share with HttpInspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    HttpFlowData* session_data = HttpInspect::http_get_flow_data(flow);

    if (session_data == nullptr)
    {
        HttpInspect::http_set_flow_data(flow, session_data = new HttpFlowData(flow));
        HttpModule::increment_peg_counts(PEG_FLOW);
    }

#ifdef REG_TEST
    if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
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
    }
#endif

    SectionType& type = session_data->type_expected[source_id];
    session_data->partial_flush[source_id] = false;

    if (type == SEC_ABORT)
        return status_value(StreamSplitter::ABORT);

    if (length > MAX_OCTETS)
    {
        assert(false);
        type = SEC_ABORT;
        return status_value(StreamSplitter::ABORT);
    }

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP) &&
        !HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
    {
        fprintf(HttpTestManager::get_output_file(), "Scan from flow data %" PRIu64
            " direction %d length %u client port %hu server port %hu\n", session_data->seq_num,
            source_id, length, flow->client_port, flow->server_port);
        fflush(HttpTestManager::get_output_file());
        if (HttpTestManager::get_show_scan())
        {
            Field(length, data).print(HttpTestManager::get_output_file(), "Scan segment");
        }
    }
#endif

    if (session_data->tcp_close[source_id])
    {
        // assert(false); // FIXIT-L This currently happens. Add assert back when problem resolved.
        type = SEC_ABORT;
        return status_value(StreamSplitter::ABORT);
    }

    // If the last request was a CONNECT and we have not yet seen the response, this is early C2S
    // traffic. If there has been a pipeline overflow or underflow we cannot match requests to
    // responses, so there is no attempt to track early C2S traffic.
    if ((source_id == SRC_CLIENT) && (type == SEC_REQUEST) && !session_data->for_http2 &&
        session_data->last_request_was_connect)
    {
        const uint64_t last_request_trans_num = session_data->expected_trans_num[SRC_CLIENT] - 1;
        const bool server_behind_connect =
            (session_data->expected_trans_num[SRC_SERVER] < last_request_trans_num);
        const bool server_expecting_connect_status =
            ((session_data->expected_trans_num[SRC_SERVER] == last_request_trans_num)
            && (session_data->type_expected[SRC_SERVER] == SEC_STATUS));
        const bool pipeline_valid = !session_data->pipeline_overflow &&
            !session_data->pipeline_underflow;

        if ((server_behind_connect || server_expecting_connect_status) && pipeline_valid)
        {
            *session_data->get_infractions(source_id) += INF_EARLY_C2S_TRAFFIC_AFTER_CONNECT;
            session_data->events[source_id]->create_event(EVENT_EARLY_C2S_TRAFFIC_AFTER_CONNECT);
            session_data->last_connect_trans_w_early_traffic =
                session_data->expected_trans_num[SRC_CLIENT] - 1;
        }
        session_data->last_request_was_connect = false;
    }

    HttpModule::increment_peg_counts(PEG_SCAN);

    if (session_data->detection_status[source_id] == DET_REACTIVATING)
    {
        if (source_id == SRC_CLIENT)
        {
            flow->set_to_server_detection(true);
        }
        else
        {
            flow->set_to_client_detection(true);
        }
        session_data->detection_status[source_id] = DET_ON;
    }

    // Check for 0.9 response message
    if ((type == SEC_STATUS) &&
        (session_data->expected_trans_num[SRC_SERVER] == session_data->zero_nine_expected))
    {
        // 0.9 response is a body that runs to connection end with no headers. HttpInspect does
        // not support no headers. Processing this imaginary status line and empty headers allows
        // us to overcome this limitation and reuse the entire HTTP infrastructure.
        prepare_flush(session_data, nullptr, SEC_STATUS, 14, 0, 0, false, 0, 14);
        my_inspector->process((const uint8_t*)"HTTP/0.9 200 .", 14, flow, SRC_SERVER, false);
        session_data->transaction[SRC_SERVER]->clear_section();
        prepare_flush(session_data, nullptr, SEC_HEADER, 0, 0, 0, false, 0, 0);
        my_inspector->process((const uint8_t*)"", 0, flow, SRC_SERVER, false);
        session_data->transaction[SRC_SERVER]->clear_section();
    }

    HttpCutter*& cutter = session_data->cutter[source_id];
    if (cutter == nullptr)
    {
        cutter = get_cutter(type, session_data);
    }
    const uint32_t max_length = MAX_OCTETS - cutter->get_octets_seen();
    const ScanResult cut_result = cutter->cut(data, (length <= max_length) ? length :
        max_length, session_data->get_infractions(source_id), session_data->events[source_id],
        session_data->section_size_target[source_id],
        session_data->stretch_section_to_packet[source_id],
        session_data->h2_body_state[source_id]);
    switch (cut_result)
    {
    case SCAN_NOT_FOUND:
    case SCAN_NOT_FOUND_ACCELERATE:
        if (cutter->get_octets_seen() == MAX_OCTETS)
        {
            *session_data->get_infractions(source_id) += INF_ENDLESS_HEADER;
            // FIXIT-L the following call seems inappropriate for headers and trailers. Those cases
            // should be an unconditional EVENT_LOSS_OF_SYNC.
            session_data->events[source_id]->generate_misformatted_http(data, length);
            // FIXIT-E need to process this data not just discard it.
            type = SEC_ABORT;
            delete cutter;
            cutter = nullptr;
            return status_value(StreamSplitter::ABORT);
        }

        if (cut_result == SCAN_NOT_FOUND_ACCELERATE)
        {
            prep_partial_flush(flow, length);
#ifdef REG_TEST
            if (!HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
#endif
                *flush_offset = length;
            return status_value(StreamSplitter::FLUSH);
        }

        // Wait patiently for more data
        return status_value(StreamSplitter::SEARCH);
    case SCAN_ABORT:
        type = SEC_ABORT;
        delete cutter;
        cutter = nullptr;
        return status_value(StreamSplitter::ABORT);
    case SCAN_DISCARD:
    case SCAN_DISCARD_PIECE:
        prepare_flush(session_data, flush_offset, SEC_DISCARD, cutter->get_num_flush(), 0, 0,
            false, 0, cutter->get_octets_seen());
        if (cut_result == SCAN_DISCARD)
        {
            delete cutter;
            cutter = nullptr;
        }
        else
            cutter->soft_reset();
        return status_value(StreamSplitter::FLUSH);
    case SCAN_FOUND:
    case SCAN_FOUND_PIECE:
      {
        const uint32_t flush_octets = cutter->get_num_flush();
        prepare_flush(session_data, flush_offset, type, flush_octets, cutter->get_num_excess(),
            cutter->get_num_head_lines(), cutter->get_is_broken_chunk(),
            cutter->get_num_good_chunks(), cutter->get_octets_seen());
        if (cut_result == SCAN_FOUND)
        {
            delete cutter;
            cutter = nullptr;
        }
        else
            cutter->soft_reset();
        return status_value(StreamSplitter::FLUSH);
      }
    default:
        assert(false);
        return status_value(StreamSplitter::ABORT);
    }
}

