//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "http_stream_splitter.h"

#include "packet_io/active.h"
#include "protocols/packet.h"

#include "http_common.h"
#include "http_context_data.h"
#include "http_cutter.h"
#include "http_enum.h"
#include "http_inspect.h"
#include "http_module.h"
#include "http_msg_section.h"
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
        if (session_data->expected_trans_num[SRC_SERVER] == session_data->zero_nine_expected)
            return (HttpCutter*)new HttpZeroNineCutter;

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
    case SEC_BODY_HX:
        return (HttpCutter*)new HttpBodyHXCutter(
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
    return scan(pkt->flow, data, length, flush_offset);
}

StreamSplitter::Status HttpStreamSplitter::handle_zero_nine(Flow* flow, HttpFlowData* session_data, const uint8_t* data, uint32_t length,
    uint32_t* flush_offset, SectionType& type, HttpCutter*& cutter)
{
    // Didn't match status line, this is a 0.9 response.
    // Delete ZeroNineCutter, save the amount of bytes that should be resent to BodyOld
    const uint32_t prev_scan_match = cutter->get_octets_seen();
    delete cutter;
    cutter = nullptr;

    // 0.9 response is a body that runs to connection end with no headers.
    // Processing this imaginary empty headers allows
    // us to overcome this limitation and reuse the entire HTTP infrastructure.
    session_data->version_id[source_id] = VERS_0_9;
    session_data->status_code_num = 200;
    HttpModule::increment_peg_counts(PEG_RESPONSE);
    prepare_flush(session_data, nullptr, SEC_HEADER, 0, 0, 0, false, 0, 0);
    my_inspector->process((const uint8_t*)"", 0, flow, SRC_SERVER, false, nullptr);
    session_data->transaction[SRC_SERVER]->clear_section();
    HttpContextData* hcd = (HttpContextData*)DetectionEngine::get_data(HttpContextData::ips_id);
    assert(hcd != nullptr);
    if (hcd == nullptr)
    {
        type = SEC_ABORT;
        return status_value(StreamSplitter::ABORT);
    }
    hcd->clear();

    // Call BodyOldCutter
    StreamSplitter::Status status;
    if (prev_scan_match)
    {
        assert(prev_scan_match < HttpZeroNineCutter::match_size);
        uint8_t* buffer = new uint8_t[length + prev_scan_match];
        memcpy (buffer, HttpZeroNineCutter::match, prev_scan_match);
        memcpy (buffer + prev_scan_match, data, length);
        status = call_cutter(flow, session_data, buffer, length + prev_scan_match, flush_offset, type);
        delete[] buffer;
    }
    else
        status = call_cutter(flow, session_data, data, length, flush_offset, type);

    return status;
}

StreamSplitter::Status HttpStreamSplitter::call_cutter(Flow* flow, HttpFlowData* session_data, const uint8_t* data, uint32_t length,
    uint32_t* flush_offset, SectionType& type)
{
    HttpCutter*& cutter = session_data->cutter[source_id];
    if (cutter == nullptr)
    {
        cutter = get_cutter(type, session_data);
    }

    const uint32_t max_length = MAX_OCTETS - cutter->get_octets_seen();
    ScanResult cut_result = cutter->cut(data, (length <= max_length) ? length :
        max_length, session_data->get_infractions(source_id), session_data->events[source_id],
        session_data->section_size_target[source_id],
        session_data->stretch_section_to_packet[source_id],
        session_data->hx_body_state[source_id]);
    switch (cut_result)
    {
    case SCAN_NOT_FOUND:
    case SCAN_NOT_FOUND_ACCELERATE:
        if (cutter->get_octets_seen() == MAX_OCTETS)
        {
            *session_data->get_infractions(source_id) += INF_ENDLESS_HEADER;
            auto event = HttpEnums::EVENT_HEADERS_TOO_LONG;

            if (session_data ->type_expected[source_id] == HttpCommon::SEC_REQUEST)
                event = HttpEnums::EVENT_REQ_TOO_LONG;
            else if (session_data ->type_expected[source_id] == HttpCommon::SEC_STATUS)
                event = HttpEnums::EVENT_STAT_TOO_LONG;

            session_data->events[source_id]->create_event(event);
            session_data->events[source_id]->create_event(HttpEnums::EVENT_LOSS_OF_SYNC);
            type = SEC_ABORT;
            delete cutter;
            cutter = nullptr;
            return status_value(StreamSplitter::ABORT);
        }

        if (source_id == SRC_CLIENT)
        {
            int64_t partial_depth = 0;
            auto params = my_inspector->params;

            if (type == SEC_HEADER)
            {
                if (params->partial_depth_header != 0 && !session_data->for_httpx)
                    partial_depth = params->partial_depth_header;
            }
            else if (is_body(type))
            {
                if (params->partial_depth_body != 0 &&
                    (params->partial_depth_body == -1 || cutter->get_num_flush() == 0))
                    partial_depth = params->partial_depth_body;
            }

            if (partial_depth == -1 || cutter->get_octets_seen() < partial_depth)
            {
                static const uint64_t MAX_PARTIAL_FLUSH_COUNTER = 20;
                if (++session_data->partial_flush_counter == MAX_PARTIAL_FLUSH_COUNTER)
                    session_data->events[source_id]->create_event(HttpEnums::EVENT_MAX_PARTIAL_FLUSH);
                cut_result = SCAN_NOT_FOUND_ACCELERATE;
            }
        }

        if (cut_result == SCAN_NOT_FOUND_ACCELERATE)
        {
            prep_partial_flush(flow, length, cutter->get_num_excess(), cutter->get_num_head_lines());
#ifdef REG_TEST
            if (!HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
#endif
                *flush_offset = length;
            return status_value(StreamSplitter::FLUSH);
        }

        // Wait patiently for more data
        return status_value(StreamSplitter::SEARCH);
    case SCAN_ABORT:
        if (type == SEC_STATUS && session_data->expected_trans_num[SRC_SERVER] == session_data->zero_nine_expected)
            return handle_zero_nine(flow, session_data, data, length, flush_offset, type, cutter);
        type = SEC_ABORT;
        delete cutter;
        cutter = nullptr;
        session_data->events[source_id]->create_event(HttpEnums::EVENT_LOSS_OF_SYNC);
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
        session_data->partial_flush_counter = 0;
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
        type = SEC_ABORT;
        delete cutter;
        cutter = nullptr;
        return status_value(StreamSplitter::ABORT);
    }
}

StreamSplitter::Status HttpStreamSplitter::scan(Flow* flow, const uint8_t* data, uint32_t length,
    uint32_t* flush_offset)
{
    Profile profile(HttpModule::get_profile_stats()); // cppcheck-suppress unreadVariable

    // This is the session state information we share with HttpInspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    HttpFlowData* session_data = HttpInspect::http_get_flow_data(flow);

    if (session_data == nullptr)
    {
        HttpInspect::http_set_flow_data(flow, session_data = new HttpFlowData(flow, my_inspector->params));
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
    if ((source_id == SRC_CLIENT) && (type == SEC_REQUEST) && !session_data->for_httpx &&
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

    return call_cutter(flow, session_data, data, length, flush_offset, type);
}

