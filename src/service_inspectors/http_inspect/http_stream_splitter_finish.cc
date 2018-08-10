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
// http_stream_splitter_finish.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_api/file_flows.h"

#include "http_module.h"
#include "http_msg_request.h"
#include "http_stream_splitter.h"
#include "http_test_input.h"

using namespace HttpEnums;

bool HttpStreamSplitter::finish(snort::Flow* flow)
{
    snort::Profile profile(HttpModule::get_profile_stats());

    HttpFlowData* session_data = (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);
    // FIXIT-M - this assert has been changed to check for null session data and return false if so
    //           due to lack of reliable feedback to stream that scan has been called...if that is
    //           addressed in stream reassembly rewrite this can be reverted to an assert
    //assert(session_data != nullptr);
    if(!session_data)
        return false;

#ifdef REG_TEST
    if (HttpTestManager::use_test_output())
    {
        if (HttpTestManager::use_test_input())
        {
            if (!HttpTestManager::get_test_input_source()->finish())
                return false;
        }
        else
        {
            printf("Finish from flow data %" PRIu64 " direction %d\n", session_data->seq_num,
                source_id);
            fflush(stdout);
        }
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
            *session_data->get_infractions(source_id) += INF_PARTIAL_START;
            // FIXIT-M why not use generate_misformatted_http()?
            session_data->get_events(source_id)->create_event(EVENT_LOSS_OF_SYNC);
            return false;
        }

        uint32_t not_used;
        prepare_flush(session_data, &not_used, session_data->type_expected[source_id], 0,
            session_data->cutter[source_id]->get_num_excess(),
            session_data->cutter[source_id]->get_num_head_lines(),
            session_data->cutter[source_id]->get_is_broken_chunk(),
            session_data->cutter[source_id]->get_num_good_chunks(),
            session_data->cutter[source_id]->get_octets_seen(),
            true);
        return true;
    }

    // If the message has been truncated immediately following the start line or immediately
    // following the headers (a body was expected) then we need to process an empty section to
    // provide an inspection section. Otherwise the start line and headers won't go through
    // detection.
    if (((session_data->type_expected[source_id] == SEC_HEADER)     ||
         (session_data->type_expected[source_id] == SEC_BODY_CL)    ||
         (session_data->type_expected[source_id] == SEC_BODY_CHUNK) ||
         (session_data->type_expected[source_id] == SEC_BODY_OLD))     &&
        (session_data->cutter[source_id] == nullptr)                   &&
        (session_data->section_type[source_id] == SEC__NOT_COMPUTE))
    {
        // Set up to process empty message section
        uint32_t not_used;
        prepare_flush(session_data, &not_used, session_data->type_expected[source_id], 0, 0, 0,
            false, 0, 0, true);
        return true;
    }

    // If there is no more data to process we need to wrap up file processing right now
    if ((session_data->section_type[source_id] == SEC__NOT_COMPUTE) &&
        (session_data->file_depth_remaining[source_id] > 0)        &&
        (session_data->cutter[source_id] != nullptr)               &&
        (session_data->cutter[source_id]->get_octets_seen() == 0))
    {
        if (!session_data->mime_state[source_id])
        {
            snort::FileFlows* file_flows = snort::FileFlows::get_file_flows(flow);
            const bool download = (source_id == SRC_SERVER);

            size_t file_index = 0;

            if (session_data->transaction[source_id] != nullptr)
            {
                HttpMsgRequest* request = session_data->transaction[source_id]->get_request();
                if ((request != nullptr) and (request->get_http_uri() != nullptr))
                {
                    file_index = request->get_http_uri()->get_file_proc_hash();
                }
            }

            file_flows->file_process(nullptr, 0, SNORT_FILE_END, !download, file_index);
        }
        else
        {
            session_data->mime_state[source_id]->process_mime_data(flow, nullptr, 0, true,
                SNORT_FILE_POSITION_UNKNOWN);
            delete session_data->mime_state[source_id];
            session_data->mime_state[source_id] = nullptr;
        }
        return false;
    }

    return session_data->section_type[source_id] != SEC__NOT_COMPUTE;
}

