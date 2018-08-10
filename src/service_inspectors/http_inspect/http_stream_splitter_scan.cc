//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "http_inspect.h"
#include "http_module.h"
#include "http_stream_splitter.h"
#include "http_test_input.h"

using namespace snort;
using namespace HttpEnums;

// Convenience function. All housekeeping that must be done before we can return FLUSH to stream.
void HttpStreamSplitter::prepare_flush(HttpFlowData* session_data, uint32_t* flush_offset,
    SectionType section_type, uint32_t num_flushed, uint32_t num_excess, int32_t num_head_lines,
    bool is_broken_chunk, uint32_t num_good_chunks, uint32_t octets_seen, bool strict_length) const
{
    session_data->section_type[source_id] = section_type;
    session_data->num_excess[source_id] = num_excess;
    session_data->num_head_lines[source_id] = num_head_lines;
    session_data->is_broken_chunk[source_id] = is_broken_chunk;
    session_data->num_good_chunks[source_id] = num_good_chunks;
    session_data->octets_expected[source_id] = octets_seen + num_flushed;
    session_data->strict_length[source_id] = strict_length;

    if (flush_offset != nullptr)
    {
#ifdef REG_TEST
        if (HttpTestManager::use_test_input())
        {
            HttpTestManager::get_test_input_source()->flush(num_flushed);
        }
        else
#endif
        *flush_offset = num_flushed;
    }
}

HttpCutter* HttpStreamSplitter::get_cutter(SectionType type,
    const HttpFlowData* session_data) const
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
        return (HttpCutter*)new HttpBodyClCutter(session_data->data_length[source_id]);
    case SEC_BODY_CHUNK:
        return (HttpCutter*)new HttpBodyChunkCutter;
    case SEC_BODY_OLD:
        return (HttpCutter*)new HttpBodyOldCutter;
    default:
        assert(false);
        return nullptr;
    }
}

StreamSplitter::Status HttpStreamSplitter::scan(Flow* flow, const uint8_t* data, uint32_t length,
    uint32_t, uint32_t* flush_offset)
{
    snort::Profile profile(HttpModule::get_profile_stats());

    assert(length <= MAX_OCTETS);

    // This is the session state information we share with HttpInspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    HttpFlowData* session_data = (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);

    if (session_data == nullptr)
    {
        flow->set_flow_data(session_data = new HttpFlowData);
        HttpModule::increment_peg_counts(PEG_FLOW);
    }

    SectionType type = session_data->type_expected[source_id];

    if (type == SEC_ABORT)
        return StreamSplitter::ABORT;

#ifdef REG_TEST
    if (HttpTestManager::use_test_input())
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
    else if (HttpTestManager::use_test_output())
    {
        printf("Scan from flow data %" PRIu64
            " direction %d length %u client port %hu server port %hu\n", session_data->seq_num,
            source_id, length, flow->client_port, flow->server_port);
        fflush(stdout);
        if (HttpTestManager::get_show_scan())
        {
            Field(length, data).print(stdout, "Scan segment");
        }
    }
#endif

    assert(!session_data->tcp_close[source_id]);

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
        type = SEC_BODY_OLD;
        prepare_flush(session_data, nullptr, SEC_STATUS, 14, 0, 0, false, 0, 14, true);
        my_inspector->process((const uint8_t*)"HTTP/0.9 200 .", 14, flow, SRC_SERVER, false);
        prepare_flush(session_data, nullptr, SEC_HEADER, 0, 0, 0, false, 0, 0, true);
        my_inspector->process((const uint8_t*)"", 0, flow, SRC_SERVER, false);
    }

    HttpCutter*& cutter = session_data->cutter[source_id];
    if (cutter == nullptr)
    {
        cutter = get_cutter(type, session_data);
    }
    const uint32_t max_length = MAX_OCTETS - cutter->get_octets_seen();
    const ScanResult cut_result = cutter->cut(data, (length <= max_length) ? length :
        max_length, session_data->get_infractions(source_id), session_data->get_events(source_id),
        session_data->section_size_target[source_id], session_data->section_size_max[source_id]);
    switch (cut_result)
    {
    case SCAN_NOT_FOUND:
        if (cutter->get_octets_seen() == MAX_OCTETS)
        {
            *session_data->get_infractions(source_id) += INF_ENDLESS_HEADER;
            // FIXIT-L the following call seems inappropriate for headers and trailers. Those cases
            // should be an unconditional EVENT_LOSS_OF_SYNC.
            session_data->get_events(source_id)->generate_misformatted_http(data, length);
            // FIXIT-H need to process this data not just discard it.
            session_data->type_expected[source_id] = SEC_ABORT;
            delete cutter;
            cutter = nullptr;
            return StreamSplitter::ABORT;
        }
        // Incomplete headers wait patiently for more data
#ifdef REG_TEST
        if (HttpTestManager::use_test_input())
            return StreamSplitter::FLUSH;
        else
#endif
        return StreamSplitter::SEARCH;
    case SCAN_ABORT:
        session_data->type_expected[source_id] = SEC_ABORT;
        delete cutter;
        cutter = nullptr;
        return StreamSplitter::ABORT;
    case SCAN_DISCARD:
    case SCAN_DISCARD_PIECE:
        prepare_flush(session_data, flush_offset, SEC_DISCARD, cutter->get_num_flush(), 0, 0,
            false, 0, cutter->get_octets_seen(), true);
        if (cut_result == SCAN_DISCARD)
        {
            delete cutter;
            cutter = nullptr;
        }
        else
            cutter->soft_reset();
        return StreamSplitter::FLUSH;
    case SCAN_FOUND:
    case SCAN_FOUND_PIECE:
      {
        const uint32_t flush_octets = cutter->get_num_flush();
        prepare_flush(session_data, flush_offset, type, flush_octets, cutter->get_num_excess(),
            cutter->get_num_head_lines(), cutter->get_is_broken_chunk(),
            cutter->get_num_good_chunks(), cutter->get_octets_seen(),
            !((type == SEC_BODY_CL) || (type == SEC_BODY_OLD)));
        if (cut_result == SCAN_FOUND)
        {
            delete cutter;
            cutter = nullptr;
        }
        else
            cutter->soft_reset();
        return StreamSplitter::FLUSH;
      }
    default:
        assert(false);
        return StreamSplitter::ABORT;
    }
}

