//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_stream_splitter_finish.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_stream_splitter.h"

#include "file_api/file_flows.h"
#include "pub_sub/http_request_body_event.h"

#include "http_common.h"
#include "http_cutter.h"
#include "http_enum.h"
#include "http_field.h"
#include "http_inspect.h"
#include "http_module.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_test_input.h"

using namespace HttpCommon;
using namespace HttpEnums;
using namespace snort;

bool HttpStreamSplitter::finish(Flow* flow)
{
    // cppcheck-suppress unreadVariable
    Profile profile(HttpModule::get_profile_stats());

    HttpFlowData* session_data = HttpInspect::http_get_flow_data(flow);
    if (!session_data)
    {
        // assert(false); // FIXIT-M this should not be possible but currently it is
        return false;
    }

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
    {
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
        {
            if (!HttpTestManager::get_test_input_source()->finish())
                return false;
        }
        else
        {
            fprintf(HttpTestManager::get_output_file(),
                "Finish from flow data %" PRIu64 " direction %d\n", session_data->seq_num,
                source_id);
            fflush(HttpTestManager::get_output_file());
        }
    }
#endif

    if (session_data->type_expected[source_id] == SEC_ABORT)
    {
        return false;
    }

    if (session_data->tcp_close[source_id])
    {
        // assert(false); // FIXIT-M this should not happen but it does
        session_data->type_expected[source_id] = SEC_ABORT;
        return false;
    }

    session_data->tcp_close[source_id] = true;
    if (session_data->section_type[source_id] != SEC__NOT_COMPUTE)
        return true;

    if (session_data->type_expected[source_id] == SEC_BODY_CL)
    {
        *session_data->get_infractions(source_id) += INF_TRUNCATED_MSG_BODY_CL;
        session_data->events[source_id]->create_event(EVENT_TRUNCATED_MSG_BODY_CL);
    }
    else if (session_data->type_expected[source_id] == SEC_BODY_CHUNK)
    {
        *session_data->get_infractions(source_id) += INF_TRUNCATED_MSG_BODY_CHUNK;
        session_data->events[source_id]->create_event(EVENT_TRUNCATED_MSG_BODY_CHUNK);
    }

    // If there is leftover data for which we returned PAF_SEARCH and never flushed, we need to set
    // up to process because it is about to go to reassemble(). But we don't support partial start
    // lines.
    if ((session_data->cutter[source_id] != nullptr) &&
        (session_data->cutter[source_id]->get_octets_seen() >
        session_data->partial_raw_bytes[source_id]))
    {
        if ((session_data->type_expected[source_id] == SEC_REQUEST) ||
            (session_data->type_expected[source_id] == SEC_STATUS))
        {
            *session_data->get_infractions(source_id) += INF_PARTIAL_START;
            session_data->events[source_id]->create_event(EVENT_PARTIAL_START);
            session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
            return false;
        }

        uint32_t not_used;
        prepare_flush(session_data, &not_used, session_data->type_expected[source_id], 0,
            session_data->cutter[source_id]->get_num_excess(),
            session_data->cutter[source_id]->get_num_head_lines(),
            session_data->cutter[source_id]->get_is_broken_chunk(),
            session_data->cutter[source_id]->get_num_good_chunks(),
            session_data->cutter[source_id]->get_octets_seen());
        delete session_data->cutter[source_id];
        session_data->cutter[source_id] = nullptr;

        return true;
    }

    // If the message has been truncated immediately following the start line then we need to
    // process an empty header section to provide an inspection section. Otherwise the start line
    // won't go through detection.
    if ((session_data->type_expected[source_id] == SEC_HEADER)      &&
        (session_data->cutter[source_id] == nullptr))
    {
        // Set up to process empty header section
        uint32_t not_used;
        prepare_flush(session_data, &not_used, SEC_HEADER, 0, 0, 0, false, 0, 0);
        return true;
    }

    // If there is no more data to process we may need to tell other components
    if ((session_data->cutter[source_id] != nullptr) &&
        (session_data->cutter[source_id]->get_octets_seen() ==
            session_data->partial_raw_bytes[source_id]))
    {
        // Wrap up file processing
        if (session_data->file_depth_remaining[source_id] > 0)
        {
            Packet* packet = DetectionEngine::get_current_packet();
            if (!session_data->mime_state[source_id])
            {
                FileFlows* file_flows = FileFlows::get_file_flows(flow);
                if (!file_flows)
                    return false;

                const FileDirection dir = (source_id == SRC_SERVER) ? FILE_DOWNLOAD :
                    FILE_UPLOAD;

                assert(session_data->transaction[source_id] != nullptr);
                HttpMsgHeader* header = session_data->transaction[source_id]->
                    get_header(source_id);
                assert(header);

                uint64_t file_index = header->get_file_cache_index();
                const uint64_t file_processing_id = header->get_multi_file_processing_id();
                file_flows->file_process(packet, file_index, nullptr, 0,
                    session_data->file_octets[source_id], dir, file_processing_id,
                    SNORT_FILE_END);
#ifdef REG_TEST
                if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
                {
                    fprintf(HttpTestManager::get_output_file(),
                        "File processing finalization during finish()\n");
                    fflush(HttpTestManager::get_output_file());
                }
#endif
            }
            else
            {
                // FIXIT-M The following call does not actually accomplish anything. The MIME
                // interface needs to be enhanced so that we can communicate end-of-data
                // without side effects.
                session_data->mime_state[source_id]->process_mime_data(packet, nullptr, 0, true,
                    SNORT_FILE_POSITION_UNKNOWN);
                delete session_data->mime_state[source_id];
                session_data->mime_state[source_id] = nullptr;
#ifdef REG_TEST
                if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
                {
                    fprintf(HttpTestManager::get_output_file(),
                        "MIME finalization during finish()\n");
                    fflush(HttpTestManager::get_output_file());
                }
#endif
            }
        }
        // If we were publishing a request body need to publish that body is complete
        if (session_data->publish_depth_remaining[source_id] > 0)
        {
            HttpRequestBodyEvent http_request_body_event(nullptr,
                session_data->publish_octets[source_id], true, session_data);
            DataBus::publish(my_inspector->get_pub_id(), HttpEventIds::REQUEST_BODY, http_request_body_event, flow);
#ifdef REG_TEST
            if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
            {
                fprintf(HttpTestManager::get_output_file(),
                    "Request body event published during finish()\n");
                fflush(HttpTestManager::get_output_file());
            }
#endif
        }
        return false;
    }

    return false;
}

void HttpStreamSplitter::prep_partial_flush(Flow* flow, uint32_t num_flush)
{
    // cppcheck-suppress unreadVariable
    Profile profile(HttpModule::get_profile_stats());

    HttpFlowData* session_data = HttpInspect::http_get_flow_data(flow);
    assert(session_data != nullptr);

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP) &&
        !HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
    {
        fprintf(HttpTestManager::get_output_file(), "Partial flush from flow data %" PRIu64 "\n",
            session_data->seq_num);
        fflush(HttpTestManager::get_output_file());
    }
#endif

    // Set up to process partial message section
    uint32_t not_used;
    prepare_flush(session_data, &not_used, session_data->type_expected[source_id], num_flush, 0, 0,
        session_data->cutter[source_id]->get_is_broken_chunk(),
        session_data->cutter[source_id]->get_num_good_chunks(),
        session_data->cutter[source_id]->get_octets_seen() - num_flush);
    session_data->partial_flush[source_id] = true;
}

