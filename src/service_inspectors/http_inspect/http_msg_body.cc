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
// http_msg_body.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_body.h"

#include "file_api/file_flows.h"

#include "http_api.h"
#include "http_js_norm.h"
#include "http_msg_request.h"

using namespace snort;
using namespace HttpEnums;

HttpMsgBody::HttpMsgBody(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, snort::Flow* flow_,
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
        do_pdf_swf_decompression(decoded_body, decompressed_pdf_swf_body);
        do_js_normalization(decompressed_pdf_swf_body, js_norm_body);
        const int32_t detect_length =
            (js_norm_body.length() <= session_data->detect_depth_remaining[source_id]) ?
            js_norm_body.length() : session_data->detect_depth_remaining[source_id];
        detect_data.set(detect_length, js_norm_body.start());
        session_data->detect_depth_remaining[source_id] -= detect_length;
        snort::set_file_data(const_cast<uint8_t*>(detect_data.start()),
            (unsigned)detect_data.length());
    }

    if (session_data->file_depth_remaining[source_id] > 0)
    {
        do_file_processing(decoded_body);
    }

    body_octets += msg_text.length();
}

bool HttpMsgBody::detection_required() const
{
    return (detect_data.length() > 0) || (get_inspection_section() == IS_DETECTION);
}

void HttpMsgBody::do_utf_decoding(const Field& input, Field& output)
{
    if ((source_id == SRC_CLIENT) || (session_data->utf_state == nullptr) || (input.length() == 0))
    {
        output.set(input);
        return;
    }

    if (session_data->utf_state->is_utf_encoding_present())
    {
        int bytes_copied;
        bool decoded;
        uint8_t* buffer = new uint8_t[input.length()];
        decoded = session_data->utf_state->decode_utf(
            input.start(), input.length(), buffer, input.length(), &bytes_copied);

        if (!decoded)
        {
            delete[] buffer;
            output.set(input);
            add_infraction(INF_UTF_NORM_FAIL);
            create_event(EVENT_UTF_NORM_FAIL);
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

void HttpMsgBody::do_pdf_swf_decompression(const Field& input, Field& output)
{
    if ((source_id == SRC_CLIENT) || (session_data->fd_state == nullptr))
    {
        output.set(input);
        return;
    }
    uint8_t* buffer = new uint8_t[MAX_OCTETS];
    session_data->fd_alert_context.infractions = transaction->get_infractions(source_id);
    session_data->fd_alert_context.events = transaction->get_events(source_id);
    session_data->fd_state->Next_In = input.start();
    session_data->fd_state->Avail_In = (uint32_t)input.length();
    session_data->fd_state->Next_Out = buffer;
    session_data->fd_state->Avail_Out = MAX_OCTETS;

    const fd_status_t status = File_Decomp(session_data->fd_state);

    switch(status)
    {
    case File_Decomp_DecompError:
        File_Decomp_Alert(session_data->fd_state, session_data->fd_state->Error_Event);
        // Fall through
    case File_Decomp_NoSig:
    case File_Decomp_Error:
        delete[] buffer;
        output.set(input);
        File_Decomp_StopFree(session_data->fd_state);
        session_data->fd_state = nullptr;
        break;
    case File_Decomp_BlockOut:
        add_infraction(INF_PDF_SWF_OVERRUN);
        create_event(EVENT_PDF_SWF_OVERRUN);
        // Fall through
    default:
        output.set(session_data->fd_state->Next_Out - buffer, buffer, true);
        break;
    }
}

void HttpMsgBody::fd_event_callback(void* context, int event)
{
    HttpInfractions* infractions = ((HttpFlowData::FdCallbackContext*)context)->infractions;
    HttpEventGen* events = ((HttpFlowData::FdCallbackContext*)context)->events;
    switch (event)
    {
    case FILE_DECOMP_ERR_SWF_ZLIB_FAILURE:
        *infractions += INF_SWF_ZLIB_FAILURE;
        events->create_event(EVENT_SWF_ZLIB_FAILURE);
        break;
    case FILE_DECOMP_ERR_SWF_LZMA_FAILURE:
        *infractions += INF_SWF_LZMA_FAILURE;
        events->create_event(EVENT_SWF_LZMA_FAILURE);
        break;
    case FILE_DECOMP_ERR_PDF_DEFL_FAILURE:
        *infractions += INF_PDF_DEFL_FAILURE;
        events->create_event(EVENT_PDF_DEFL_FAILURE);
        break;
    case FILE_DECOMP_ERR_PDF_UNSUP_COMP_TYPE:
        *infractions += INF_PDF_UNSUP_COMP_TYPE;
        events->create_event(EVENT_PDF_UNSUP_COMP_TYPE);
        break;
    case FILE_DECOMP_ERR_PDF_CASC_COMP:
        *infractions += INF_PDF_CASC_COMP;
        events->create_event(EVENT_PDF_CASC_COMP);
        break;
    case FILE_DECOMP_ERR_PDF_PARSE_FAILURE:
        *infractions += INF_PDF_PARSE_FAILURE;
        events->create_event(EVENT_PDF_PARSE_FAILURE);
        break;
    default:
        assert(false);
        break;
    }
}

void HttpMsgBody::do_js_normalization(const Field& input, Field& output)
{
    if (!params->js_norm_param.normalize_javascript || source_id == SRC_CLIENT)
    {
        output.set(input);
        return;
    }

    params->js_norm_param.js_norm->normalize(input, output,
        transaction->get_infractions(source_id), transaction->get_events(source_id));
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
        snort::FileFlows* file_flows = snort::FileFlows::get_file_flows(flow);
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
                    const Field& transaction_uri = request->get_uri();
                    if (transaction_uri.length() > 0)
                    {
                        file_flows->set_file_name(transaction_uri.start(),
                            transaction_uri.length());
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
    get_classic_buffer(HTTP_BUFFER_RAW_BODY, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_BODY-1]);

    HttpMsgSection::print_section_wrapup(output);
}
#endif

