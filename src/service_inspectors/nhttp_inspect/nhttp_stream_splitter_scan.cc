//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_stream_splitter_scan.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <sys/types.h>

#include "file_api/file_flows.h"
#include "nhttp_enum.h"
#include "nhttp_field.h"
#include "nhttp_test_manager.h"
#include "nhttp_test_input.h"
#include "nhttp_cutter.h"
#include "nhttp_inspect.h"
#include "nhttp_stream_splitter.h"

using namespace NHttpEnums;

// Convenience function. All housekeeping that must be done before we can return FLUSH to stream.
void NHttpStreamSplitter::prepare_flush(NHttpFlowData* session_data, uint32_t* flush_offset,
    SectionType section_type, uint32_t num_flushed, uint32_t num_excess, int32_t num_head_lines,
    bool is_broken_chunk, uint32_t num_good_chunks) const
{
    session_data->section_type[source_id] = section_type;
    session_data->num_excess[source_id] = num_excess;
    session_data->num_head_lines[source_id] = num_head_lines;
    session_data->is_broken_chunk[source_id] = is_broken_chunk;
    session_data->num_good_chunks[source_id] = num_good_chunks;

#ifdef REG_TEST
    if (NHttpTestManager::use_test_input())
    {
        NHttpTestManager::get_test_input_source()->flush(num_flushed);
    }
    else
#endif

    *flush_offset = num_flushed;
}

NHttpCutter* NHttpStreamSplitter::get_cutter(SectionType type,
    const NHttpFlowData* session_data) const
{
    switch (type)
    {
    case SEC_REQUEST:
        return (NHttpCutter*)new NHttpRequestCutter;
    case SEC_STATUS:
        return (NHttpCutter*)new NHttpStatusCutter;
    case SEC_HEADER:
    case SEC_TRAILER:
        return (NHttpCutter*)new NHttpHeaderCutter;
    case SEC_BODY_CL:
        return (NHttpCutter*)new NHttpBodyClCutter(session_data->data_length[source_id]);
    case SEC_BODY_CHUNK:
        return (NHttpCutter*)new NHttpBodyChunkCutter;
    case SEC_BODY_OLD:
        return (NHttpCutter*)new NHttpBodyOldCutter;
    default:
        assert(false);
        return nullptr;
    }
}

StreamSplitter::Status NHttpStreamSplitter::scan(Flow* flow, const uint8_t* data, uint32_t length,
    uint32_t, uint32_t* flush_offset)
{
    assert(length <= MAX_OCTETS);

    // This is the session state information we share with NHttpInspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(
        NHttpFlowData::nhttp_flow_id);
    if (session_data == nullptr)
    {
        flow->set_application_data(session_data = new NHttpFlowData);
        NHttpModule::increment_peg_counts(PEG_FLOW);
    }

    SectionType type = session_data->type_expected[source_id];

    if (type == SEC_ABORT)
        return StreamSplitter::ABORT;

#ifdef REG_TEST
    if (NHttpTestManager::use_test_input())
    {
        // This block substitutes a completely new data buffer supplied by the test tool in place
        // of the "real" data. It also rewrites the buffer length.
        *flush_offset = length;
        uint8_t* test_data = nullptr;
        NHttpTestManager::get_test_input_source()->scan(test_data, length, source_id,
            session_data->seq_num);
        if (length == 0)
            return StreamSplitter::FLUSH;
        data = test_data;
    }
    else if (NHttpTestManager::use_test_output())
    {
        printf("Scan from flow data %" PRIu64 " direction %d length %u\n", session_data->seq_num,
            source_id, length);
        fflush(stdout);
    }
#endif

    assert(!session_data->tcp_close[source_id]);

    NHttpModule::increment_peg_counts(PEG_SCAN);

    // Check for 0.9 response message
    if ((type == SEC_STATUS) &&
        (session_data->expected_msg_num[SRC_SERVER] == session_data->zero_nine_expected))
    {
        // 0.9 response is a body that runs to connection end with no headers. NHttpInspect does
        // not support no headers. Processing this imaginary status line and empty headers allows
        // us to overcome this limitation and reuse the entire HTTP infrastructure.
        type = SEC_BODY_OLD;
        uint32_t not_used;
        prepare_flush(session_data, &not_used, SEC_STATUS, 14, 0, 0, false, 0);
        my_inspector->process((const uint8_t*)"HTTP/0.9 200 .", 14, flow, SRC_SERVER, false);
        prepare_flush(session_data, &not_used, SEC_HEADER, 0, 0, 0, false, 0);
        my_inspector->process((const uint8_t*)"", 0, flow, SRC_SERVER, false);
    }

    NHttpCutter*& cutter = session_data->cutter[source_id];
    if (cutter == nullptr)
    {
        cutter = get_cutter(type, session_data);
    }
    const uint32_t max_length = MAX_OCTETS - cutter->get_octets_seen();
    const ScanResult cut_result = cutter->cut(data, (length <= max_length) ? length :
        max_length, session_data->infractions[source_id], session_data->events[source_id],
        session_data->section_size_target[source_id], session_data->section_size_max[source_id]);
    switch (cut_result)
    {
    case SCAN_NOTFOUND:
        if (cutter->get_octets_seen() == MAX_OCTETS)
        {
            session_data->infractions[source_id] += INF_ENDLESS_HEADER;
            session_data->events[source_id].generate_misformatted_http(data, length);
            // FIXIT-H need to process this data not just discard it.
            session_data->type_expected[source_id] = SEC_ABORT;
            delete cutter;
            cutter = nullptr;
            return StreamSplitter::ABORT;
        }
        // Incomplete headers wait patiently for more data
#ifdef REG_TEST
        if (NHttpTestManager::use_test_input())
            return StreamSplitter::FLUSH;
        else
#endif
        return StreamSplitter::SEARCH;
    case SCAN_ABORT:
    case SCAN_END: // FIXIT-H need StreamSplitter::END
        session_data->type_expected[source_id] = SEC_ABORT;
        delete cutter;
        cutter = nullptr;
        return StreamSplitter::ABORT;
    case SCAN_DISCARD:
    case SCAN_DISCARD_PIECE:
        prepare_flush(session_data, flush_offset, SEC_DISCARD, cutter->get_num_flush(), 0, 0,
            false, 0);
        if (cut_result == SCAN_DISCARD)
        {
            delete cutter;
            cutter = nullptr;
        }
        return StreamSplitter::FLUSH;
    case SCAN_FOUND:
    case SCAN_FOUND_PIECE:
      {
        const uint32_t flush_octets = cutter->get_num_flush();
        prepare_flush(session_data, flush_offset, type, flush_octets, cutter->get_num_excess(),
            cutter->get_num_head_lines(), cutter->get_is_broken_chunk(),
            cutter->get_num_good_chunks());
        if (cut_result == SCAN_FOUND)
        {
            delete cutter;
            cutter = nullptr;
        }
        return StreamSplitter::FLUSH;
      }
    default:
        assert(false);
        return StreamSplitter::ABORT;
    }
}

bool NHttpStreamSplitter::finish(Flow* flow)
{
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(
        NHttpFlowData::nhttp_flow_id);

    assert(session_data != nullptr);

#ifdef REG_TEST
    if (NHttpTestManager::use_test_output() && !NHttpTestManager::use_test_input())
    {
        printf("Finish from flow data %" PRIu64 " direction %d\n", session_data->seq_num,
            source_id);
        fflush(stdout);
    }
#endif

    if (session_data->type_expected[source_id] == SEC_ABORT)
    {
        return false;
    }

    session_data->tcp_close[source_id] = true;

    // If there is leftover data for which we returned PAF_SEARCH and never flushed, we need to set
    // up to process because it is about to go to reassemble(). But we don't support partial start
    // lines.
    if ((session_data->section_type[source_id] == SEC__NOT_COMPUTE) &&
        (session_data->cutter[source_id] != nullptr)               &&
        (session_data->cutter[source_id]->get_octets_seen() > 0))
    {
        if ((session_data->type_expected[source_id] == SEC_REQUEST) ||
            (session_data->type_expected[source_id] == SEC_STATUS))
        {
            session_data->infractions[source_id] += INF_PARTIAL_START;
            session_data->events[source_id].create_event(EVENT_LOSS_OF_SYNC);
            return false;
        }

        uint32_t not_used;
        prepare_flush(session_data, &not_used, session_data->type_expected[source_id], 0, 0,
            session_data->cutter[source_id]->get_num_head_lines() + 1,
            session_data->cutter[source_id]->get_is_broken_chunk(),
            session_data->cutter[source_id]->get_num_good_chunks());
        return true;
    }

    // If there is no more data to process we need to wrap up file processing right now
    if ((session_data->section_type[source_id] == SEC__NOT_COMPUTE) &&
        (session_data->file_depth_remaining[source_id] > 0)        &&
        (session_data->cutter[source_id] != nullptr)               &&
        (session_data->cutter[source_id]->get_octets_seen() == 0))
    {
        if (source_id == SRC_SERVER)
        {
            FileFlows* file_flows = FileFlows::get_file_flows(flow);
            file_flows->file_process(nullptr, 0, SNORT_FILE_END, false);
        }
        else if (session_data->mime_state != nullptr)
        {
            session_data->mime_state->process_mime_data(flow, nullptr, 0, true,
                SNORT_FILE_END);
            delete session_data->mime_state;
            session_data->mime_state = nullptr;
        }
        return false;
    }

    return true;
}

