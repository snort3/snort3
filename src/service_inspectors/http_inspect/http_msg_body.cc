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
// http_msg_body.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_body.h"

#include "file_api/file_flows.h"

#include "http_api.h"
#include "http_js_norm.h"
#include "http_msg_request.h"

using namespace HttpEnums;

HttpMsgBody::HttpMsgBody(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_),
    body_octets(session_data->body_octets[source_id]),
    detection_section((body_octets == 0) && (session_data->detect_depth_remaining[source_id] > 0))
{
    transaction->set_body(this);
}

void HttpMsgBody::analyze()
{
    do_utf_decoding(msg_text, decoded_body);

    if (session_data->detect_depth_remaining[source_id] > 0)
    {
        do_js_normalization(decoded_body, js_norm_body);
        const int32_t detect_length =
            (js_norm_body.length() <= session_data->detect_depth_remaining[source_id]) ?
            js_norm_body.length() : session_data->detect_depth_remaining[source_id];
        detect_data.set(detect_length, js_norm_body.start());
        session_data->detect_depth_remaining[source_id] -= detect_length;
        // Always set file data. File processing will later set a new value in some cases.
        set_file_data(const_cast<uint8_t*>(detect_data.start()), (unsigned)detect_data.length());
    }

    if (session_data->file_depth_remaining[source_id] > 0)
    {
        do_file_processing(decoded_body);
    }

    body_octets += msg_text.length();
}

void HttpMsgBody::do_utf_decoding(const Field& input, Field& output)
{
    if (!params->normalize_utf || source_id == SRC_CLIENT)
    {
        output.set(input);
        return;
    }

    if (session_data->utf_state && session_data->utf_state->is_utf_encoding_present())
    {
        int bytes_copied;
        bool decoded;
        uint8_t* buffer = new uint8_t[input.length()];
        decoded = session_data->utf_state->decode_utf((const char*)input.start(), input.length(),
                            (char*)buffer, input.length(), &bytes_copied);
        if (!decoded)
        {
            delete[] buffer;
            output.set(input);
            infractions += INF_UTF_NORM_FAIL;
            events.create_event(EVENT_UTF_NORM_FAIL);
        }
        else if (bytes_copied > 0)
        {
            output.set(bytes_copied, buffer, true);
        }
        else
        {
            delete[] buffer;
            output.set(input);
        }
    }

    else
        output.set(input);
}

void HttpMsgBody::do_js_normalization(const Field& input, Field& output)
{
    if (!params->js_norm_param.normalize_javascript || source_id == SRC_CLIENT)
    {
        output.set(input);
        return;
    }

    params->js_norm_param.js_norm->normalize(input, output, infractions, events);
}

void HttpMsgBody::do_file_processing(Field& file_data)
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
    if (front && (file_data.length() == 0))
    {
        return;
    }

    const int32_t fp_length = (file_data.length() <= session_data->file_depth_remaining[source_id])
        ? file_data.length() : session_data->file_depth_remaining[source_id];

    if (!session_data->mime_state[source_id])
    {
        FileFlows* file_flows = FileFlows::get_file_flows(flow);
        const bool download = (source_id == SRC_SERVER);

        HttpMsgRequest* request = transaction->get_request();

        size_t file_index = 0;

        if ((request != nullptr) and (request->get_http_uri() != nullptr))
        {
            file_index = request->get_http_uri()->get_file_proc_hash();
        }

        if (file_flows->file_process(file_data.start(), fp_length,
            file_position, !download, file_index))
        {
            session_data->file_depth_remaining[source_id] -= fp_length;

            // With the first piece of the file we must provide the "name" which means URI
            if (front)
            {
                if (request != nullptr)
                {
                    const Field& tranaction_uri = request->get_uri_norm_classic();
                    if (tranaction_uri.length() > 0)
                    {
                        file_flows->set_file_name(tranaction_uri.start(), tranaction_uri.length());
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
        session_data->mime_state[source_id]->process_mime_data(flow, file_data.start(),
            fp_length, true, SNORT_FILE_POSITION_UNKNOWN);

        session_data->file_depth_remaining[source_id] -= fp_length;
        if (session_data->file_depth_remaining[source_id] == 0)
        {
            delete session_data->mime_state[source_id];
            session_data->mime_state[source_id] = nullptr;
        }
    }
}

const Field& HttpMsgBody::get_classic_client_body()
{
    return classic_normalize(detect_data, classic_client_body, params->uri_param);
}

#ifdef REG_TEST
// Common elements of print_section() for body sections
void HttpMsgBody::print_body_section(FILE* output)
{
    detect_data.print(output, "Detect data");
    get_classic_buffer(HTTP_BUFFER_CLIENT_BODY, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_CLIENT_BODY-1]);

    DataPointer& body = get_file_data();
    if (body.len > 0)
    {
        Field(body.len, body.data).print(output, "file_data");
    }
    HttpMsgSection::print_section_wrapup(output);
}
#endif

