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
// http_msg_body.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_body.h"

#include "file_api/file_flows.h"

#include "http_api.h"
#include "http_common.h"
#include "http_enum.h"
#include "http_js_norm.h"
#include "http_msg_header.h"
#include "http_msg_request.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

HttpMsgBody::HttpMsgBody(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgSection(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_),
    body_octets(session_data->body_octets[source_id]),
    first_body(session_data->body_octets[source_id] == 0)
{
    transaction->set_body(this);
    get_related_sections();
}

void HttpMsgBody::bookkeeping_regular_flush(uint32_t& partial_detect_length,
    uint8_t*& partial_detect_buffer, uint32_t& partial_js_detect_length, int32_t detect_length)
{
    session_data->detect_depth_remaining[source_id] -= detect_length;
    partial_detect_buffer = nullptr;
    partial_detect_length = 0;
    partial_js_detect_length = 0;
}

void HttpMsgBody::clean_partial(uint32_t& partial_inspected_octets, uint32_t& partial_detect_length,
    uint8_t*& partial_detect_buffer, uint32_t& partial_js_detect_length, int32_t detect_length)
{
    body_octets += msg_text.length();
    partial_inspected_octets = session_data->partial_flush[source_id] ? msg_text.length() : 0;

    if (session_data->partial_flush[source_id])
        return;

    if (session_data->detect_depth_remaining[source_id] > 0)
    {
        delete[] partial_detect_buffer;
        session_data->update_deallocations(partial_detect_length);
        assert(detect_length <= session_data->detect_depth_remaining[source_id]);
        bookkeeping_regular_flush(partial_detect_length, partial_detect_buffer, partial_js_detect_length,
            detect_length);
    }
}

void HttpMsgBody::analyze()
{
    uint32_t& partial_inspected_octets = session_data->partial_inspected_octets[source_id];

    // When there have been partial inspections we focus on the part of the message we have not
    // seen before
    if (partial_inspected_octets > 0)
    {
        assert(msg_text.length() >= (int32_t)partial_inspected_octets);
        // For regular flush, file processing needs to be finalized.
        // Continue even if there is no new information
        if ((msg_text.length() == (int32_t)partial_inspected_octets)
            && session_data->partial_flush[source_id])
            return;

        msg_text_new.set(msg_text.length() - partial_inspected_octets,
            msg_text.start() + partial_inspected_octets);
    }
    else
        msg_text_new.set(msg_text);

    do_utf_decoding(msg_text_new, decoded_body);

    if (session_data->file_depth_remaining[source_id] > 0)
    {
        do_file_processing(decoded_body);
    }

    if (session_data->detect_depth_remaining[source_id] > 0)
    {
        do_file_decompression(decoded_body, decompressed_file_body);

        uint32_t& partial_detect_length = session_data->partial_detect_length[source_id];
        uint8_t*& partial_detect_buffer = session_data->partial_detect_buffer[source_id];
        uint32_t& partial_js_detect_length = session_data->partial_js_detect_length[source_id];

        if (partial_detect_length > 0)
        {
            const int32_t total_length = partial_detect_length + decompressed_file_body.length();
            uint8_t* const cumulative_buffer = new uint8_t[total_length];
            memcpy(cumulative_buffer, partial_detect_buffer, partial_detect_length);
            memcpy(cumulative_buffer + partial_detect_length, decompressed_file_body.start(),
                decompressed_file_body.length());
            cumulative_data.set(total_length, cumulative_buffer, true);
            do_js_normalization(cumulative_data, js_norm_body);
            if ((int32_t)partial_js_detect_length == js_norm_body.length())
            {
                clean_partial(partial_inspected_octets, partial_detect_length,
                    partial_detect_buffer, partial_js_detect_length, js_norm_body.length());
                return;
            }
        }
        else
            do_js_normalization(decompressed_file_body, js_norm_body);

        const int32_t detect_length =
            (js_norm_body.length() <= session_data->detect_depth_remaining[source_id]) ?
            js_norm_body.length() : session_data->detect_depth_remaining[source_id];

        detect_data.set(detect_length, js_norm_body.start());

        delete[] partial_detect_buffer;
        session_data->update_deallocations(partial_detect_length);

        if (!session_data->partial_flush[source_id])
        {
            bookkeeping_regular_flush(partial_detect_length, partial_detect_buffer,
                partial_js_detect_length, detect_length);
        }
        else
        {
            Field* decompressed = (cumulative_data.length() > 0) ?
                &cumulative_data : &decompressed_file_body;
            uint8_t* const save_partial = new uint8_t[decompressed->length()];
            memcpy(save_partial, decompressed->start(), decompressed->length());
            partial_detect_buffer = save_partial;
            partial_detect_length = decompressed->length();
            partial_js_detect_length = js_norm_body.length();
            session_data->update_allocations(partial_detect_length);
        }

        set_file_data(const_cast<uint8_t*>(detect_data.start()),
            (unsigned)detect_data.length());
    }

    body_octets += msg_text.length();
    partial_inspected_octets = session_data->partial_flush[source_id] ? msg_text.length() : 0;
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

void HttpMsgBody::do_file_decompression(const Field& input, Field& output)
{
    if ((source_id == SRC_CLIENT) || (session_data->fd_state == nullptr))
    {
        output.set(input);
        return;
    }
    uint8_t* buffer = new uint8_t[MAX_OCTETS];
    session_data->fd_alert_context.infractions = transaction->get_infractions(source_id);
    session_data->fd_alert_context.events = session_data->events[source_id];
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
        add_infraction(INF_FILE_DECOMPR_OVERRUN);
        create_event(EVENT_FILE_DECOMPR_OVERRUN);
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
    if ( !params->js_norm_param.is_javascript_normalization or source_id == SRC_CLIENT )
        output.set(input);
    else if ( params->js_norm_param.normalize_javascript )
        params->js_norm_param.js_norm->legacy_normalize(input, output,
            transaction->get_infractions(source_id), session_data->events[source_id],
            params->js_norm_param.max_javascript_whitespaces);
    else if ( params->js_norm_param.js_normalization_depth )
    {
        output.set(input);

        params->js_norm_param.js_norm->enhanced_normalize(input, enhanced_js_norm_body,
            transaction->get_infractions(source_id), session_data->events[source_id],
            params->js_norm_param.js_normalization_depth);

        const int32_t norm_length =
            (enhanced_js_norm_body.length() <= session_data->detect_depth_remaining[source_id]) ?
            enhanced_js_norm_body.length() : session_data->detect_depth_remaining[source_id];

        if ( norm_length > 0 )
            set_script_data(enhanced_js_norm_body.start(), (unsigned int)norm_length);
    }
}

void HttpMsgBody::do_file_processing(const Field& file_data)
{
    // Using the trick that cutter is deleted when regular or chunked body is complete
    Packet* p = DetectionEngine::get_current_packet();
    const bool front = (body_octets == 0) &&
        (session_data->partial_inspected_octets[source_id] == 0);
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

    if (!session_data->mime_state[source_id])
    {
        const int32_t fp_length = (file_data.length() <=
            session_data->file_depth_remaining[source_id]) ?
            file_data.length() : session_data->file_depth_remaining[source_id];

        FileFlows* file_flows = FileFlows::get_file_flows(flow);
        if (!file_flows)
            return;

        const FileDirection dir = source_id == SRC_SERVER ? FILE_DOWNLOAD : FILE_UPLOAD;
        Field cont_disp_filename;

        const uint64_t file_index = get_header(source_id)->get_file_cache_index();

        bool continue_processing_file = file_flows->file_process(p, file_index, file_data.start(),
            fp_length, session_data->file_octets[source_id], dir,
            get_header(source_id)->get_multi_file_processing_id(), file_position);
        if (continue_processing_file)
        {
            session_data->file_depth_remaining[source_id] -= fp_length;

            // With the first piece of the file we must provide the "name". If an upload contains a
            // filename in a Content-Disposition header, we use that. Otherwise the name is the URI.
            if (front)
            {
                if (request != nullptr)
                {
                    bool has_cd_filename = false;
                    if (dir == FILE_UPLOAD)
                    {
                        const Field& cd_filename = get_header(source_id)->
                            get_content_disposition_filename();
                        if (cd_filename.length() > 0)
                        {
                            continue_processing_file = file_flows->set_file_name(
                                cd_filename.start(), cd_filename.length(), 0, 
                                get_header(source_id)->get_multi_file_processing_id());
                            has_cd_filename = true;
                        }
                    }
                    if (!has_cd_filename)
                    {
                        const Field& transaction_uri = request->get_uri();
                        if (transaction_uri.length() > 0)
                        {
                            continue_processing_file = file_flows->set_file_name(
                                transaction_uri.start(), transaction_uri.length(), 0,
                                get_header(source_id)->get_multi_file_processing_id());
                        }
                    }
                }
            }
        }
        if (!continue_processing_file)
        {
            // file processing doesn't want any more data
            session_data->file_depth_remaining[source_id] = 0;
        }
        session_data->file_octets[source_id] += fp_length;
    }
    else
    {
        // FIXIT-M this interface does not convey any indication of end of message body. If the
        // message body ends in the middle of a MIME message the partial file will not be flushed.
        session_data->mime_state[source_id]->process_mime_data(p, file_data.start(),
            file_data.length(), true, SNORT_FILE_POSITION_UNKNOWN);
        session_data->file_octets[source_id] += file_data.length();
    }
}

const Field& HttpMsgBody::get_classic_client_body()
{
    return classic_normalize(detect_data, classic_client_body, false, params->uri_param);
}

#ifdef REG_TEST
// Common elements of print_section() for body sections
void HttpMsgBody::print_body_section(FILE* output, const char* body_type_str)
{
    HttpMsgSection::print_section_title(output, body_type_str);
    fprintf(output, "octets seen %" PRIi64 "\n", body_octets);
    detect_data.print(output, "Detect data");
    get_classic_buffer(HTTP_BUFFER_CLIENT_BODY, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_CLIENT_BODY-1]);
    get_classic_buffer(HTTP_BUFFER_RAW_BODY, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_BODY-1]);

    HttpMsgSection::print_section_wrapup(output);
}
#endif

