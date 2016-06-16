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
// nhttp_msg_body.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "detection/detection_util.h"
#include "file_api/file_api.h"
#include "file_api/file_flows.h"
#include "mime/file_mime_process.h"

#include "nhttp_enum.h"
#include "nhttp_api.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_body.h"

using namespace NHttpEnums;

NHttpMsgBody::NHttpMsgBody(const uint8_t* buffer, const uint16_t buf_size,
    NHttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const NHttpParaList* params_) :
    NHttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_),
    body_octets(session_data->body_octets[source_id]),
    detection_section((body_octets == 0) && (session_data->detect_depth_remaining[source_id] > 0))
{
    transaction->set_body(this);
}

NHttpMsgBody::~NHttpMsgBody()
{
    if (classic_client_body_alloc)
        classic_client_body.delete_buffer();
}

void NHttpMsgBody::analyze()
{
    detect_data.length = (msg_text.length <= session_data->detect_depth_remaining[source_id]) ?
       msg_text.length : session_data->detect_depth_remaining[source_id];
    detect_data.start = msg_text.start;
    session_data->detect_depth_remaining[source_id] -= detect_data.length;

    // Always set file data. File processing will later set a new value in some cases.
    file_data.length = detect_data.length;
    if (file_data.length > 0)
    {
        file_data.start = msg_text.start;
        set_file_data(const_cast<uint8_t*>(file_data.start), (unsigned)file_data.length);
    }

    if (session_data->file_depth_remaining[source_id] > 0)
    {
        do_file_processing();
    }

    body_octets += msg_text.length;
}

void NHttpMsgBody::do_file_processing()
{
    // Using the trick that cutter is deleted when regular or chunked body is complete
    const bool front = (body_octets == 0);
    const bool back = (session_data->cutter[source_id] == nullptr) || tcp_close;
    FilePosition file_position;
    if (front && back) file_position = SNORT_FILE_FULL;
    else if (front) file_position = SNORT_FILE_START;
    else if (back) file_position = SNORT_FILE_END;
    else file_position = SNORT_FILE_MIDDLE;

    // Chunked body with nothing but the zero length chunk?
    if (front && (file_data.length == 0))
    {
        return;
    }

    const int32_t fp_length = (file_data.length <= session_data->file_depth_remaining[source_id]) ?
        file_data.length : session_data->file_depth_remaining[source_id];

    if (source_id == SRC_SERVER)
    {
        FileFlows* file_flows = FileFlows::get_file_flows(flow);

        if (file_flows->file_process(file_data.start, fp_length,
            file_position, false))
        {
            session_data->file_depth_remaining[source_id] -= fp_length;

            // With the first piece of the file we must provide the "name" which means URI
            if (front)
            {
                NHttpMsgRequest* request = transaction->get_request();
                if (request != nullptr)
                {
                    const Field& tranaction_uri = request->get_uri_norm_classic();
                    if (tranaction_uri.length > 0)
                    {
                        file_flows->set_file_name(tranaction_uri.start, tranaction_uri.length);
                    }
                }
            }
        }
        else
        {
            // file processing doesn't want any more data
            session_data->file_depth_remaining[source_id] = 0;
        }
    }
    else
    {
        session_data->mime_state->process_mime_data(flow, file_data.start,
            fp_length, true, file_position);

        session_data->file_depth_remaining[source_id] -= fp_length;
        if (session_data->file_depth_remaining[source_id] == 0)
        {
            delete session_data->mime_state;
            session_data->mime_state = nullptr;
        }
    }
}

const Field& NHttpMsgBody::get_classic_client_body()
{
    return classic_normalize(detect_data, classic_client_body, classic_client_body_alloc,
        params->uri_param);
}

#ifdef REG_TEST
// Common elements of print_section() for body sections
void NHttpMsgBody::print_body_section(FILE* output)
{
    detect_data.print(output, "Detect data");
    get_classic_buffer(NHTTP_BUFFER_CLIENT_BODY, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_CLIENT_BODY-1]);
    if (g_file_data.len > 0)
    {
        Field(g_file_data.len, g_file_data.data).print(output, "file_data");
    }
    NHttpMsgSection::print_section_wrapup(output);
}
#endif

