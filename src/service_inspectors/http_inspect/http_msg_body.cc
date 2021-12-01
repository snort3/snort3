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

#include "decompress/file_olefile.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "pub_sub/http_request_body_event.h"

#include "http_api.h"
#include "http_common.h"
#include "http_enum.h"
#include "http_js_norm.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_test_manager.h"
#include "http_uri.h"

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

void HttpMsgBody::publish()
{
    if (publish_length <= 0)
        return;

    const int32_t& pub_depth_remaining = session_data->publish_depth_remaining[source_id];
    int32_t& publish_octets = session_data->publish_octets[source_id];
    const bool last_piece = (session_data->cutter[source_id] == nullptr) || tcp_close ||
        (pub_depth_remaining == 0);

    HttpRequestBodyEvent http_request_body_event(this, publish_octets, last_piece, session_data);

    DataBus::publish(HTTP2_REQUEST_BODY_EVENT_KEY, http_request_body_event, flow);
    publish_octets += publish_length;
#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
    {
        fprintf(HttpTestManager::get_output_file(),
            "Published %" PRId32 " bytes of request body. last: %s\n", publish_length,
            (last_piece ? "true" : "false"));
        fflush(HttpTestManager::get_output_file());
    }
#endif
}

void HttpMsgBody::bookkeeping_regular_flush(uint32_t& partial_detect_length,
    uint8_t*& partial_detect_buffer, uint32_t& partial_js_detect_length, int32_t detect_length)
{
    params->js_norm_param.js_norm->set_detection_depth(session_data->detect_depth_remaining[source_id]);

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
        assert(detect_length <= session_data->detect_depth_remaining[source_id]);
        bookkeeping_regular_flush(partial_detect_length, partial_detect_buffer,
            partial_js_detect_length, detect_length);
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
    {
        // First flush of inspection section - set full file decompress buffer size
        session_data->file_decomp_buffer_size_remaining[source_id] =
            FileService::decode_conf.get_decompress_buffer_size();
        msg_text_new.set(msg_text);
    }

    int32_t& pub_depth_remaining = session_data->publish_depth_remaining[source_id];
    if (pub_depth_remaining > 0)
    {
        publish_length = (pub_depth_remaining > msg_text_new.length()) ?
            msg_text_new.length() : pub_depth_remaining;
        pub_depth_remaining -= publish_length;
    }

    if (session_data->file_depth_remaining[source_id] > 0 or
        session_data->detect_depth_remaining[source_id] > 0)
    {
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
                const int32_t total_length = partial_detect_length +
                    decompressed_file_body.length();
                assert(total_length <=
                    (int64_t)FileService::decode_conf.get_decompress_buffer_size());
                uint8_t* const cumulative_buffer = new uint8_t[total_length];
                memcpy(cumulative_buffer, partial_detect_buffer, partial_detect_length);
                memcpy(cumulative_buffer + partial_detect_length, decompressed_file_body.start(),
                    decompressed_file_body.length());
                cumulative_data.set(total_length, cumulative_buffer, true);
                do_legacy_js_normalization(cumulative_data, js_norm_body);
                if ((int32_t)partial_js_detect_length == js_norm_body.length())
                {
                    clean_partial(partial_inspected_octets, partial_detect_length,
                        partial_detect_buffer, partial_js_detect_length, js_norm_body.length());
                    return;
                }
            }
            else
                do_legacy_js_normalization(decompressed_file_body, js_norm_body);

            ++session_data->pdu_idx;

            const int32_t detect_length =
                (js_norm_body.length() <= session_data->detect_depth_remaining[source_id]) ?
                js_norm_body.length() : session_data->detect_depth_remaining[source_id];

            detect_data.set(detect_length, js_norm_body.start());

            delete[] partial_detect_buffer;

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
            }

            set_file_data(const_cast<uint8_t*>(detect_data.start()),
                (unsigned)detect_data.length());
        }
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

void HttpMsgBody::get_ole_data()
{
    uint8_t* ole_data_ptr;
    uint32_t ole_len;

    session_data->fd_state->get_ole_data(ole_data_ptr, ole_len);

    if (ole_data_ptr)
    {
        ole_data.set(ole_len, ole_data_ptr, false);

        //Reset the ole data ptr once it is stored in msg body
        session_data->fd_state->ole_data_reset();
    }
}
    
void HttpMsgBody::do_file_decompression(const Field& input, Field& output)
{
    if ((source_id == SRC_CLIENT) || (session_data->fd_state == nullptr))
    {
        output.set(input);
        return;
    }
    const uint32_t buffer_size = session_data->file_decomp_buffer_size_remaining[source_id];
    uint8_t* buffer = new uint8_t[buffer_size];
    session_data->fd_alert_context.infractions = transaction->get_infractions(source_id);
    session_data->fd_alert_context.events = session_data->events[source_id];
    session_data->fd_state->Next_In = input.start();
    session_data->fd_state->Avail_In = (uint32_t)input.length();
    session_data->fd_state->Next_Out = buffer;
    session_data->fd_state->Avail_Out = buffer_size;

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
        const uint32_t output_length = session_data->fd_state->Next_Out - buffer;
        output.set(output_length, buffer, true);
        assert((uint64_t)session_data->file_decomp_buffer_size_remaining[source_id] >=
            output_length);
        session_data->file_decomp_buffer_size_remaining[source_id] -= output_length;
        get_ole_data();

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

void HttpMsgBody::do_enhanced_js_normalization(const Field& input, Field& output)
{
    if (session_data->js_data_lost_once)
        return;

    auto infractions = transaction->get_infractions(source_id);
    auto back = !session_data->partial_flush[source_id];
    auto http_header = get_header(source_id);
    auto normalizer = params->js_norm_param.js_norm;

    if (session_data->is_pdu_missed())
    {
        *infractions += INF_JS_PDU_MISS;
        session_data->events[HttpCommon::SRC_SERVER]->create_event(EVENT_JS_PDU_MISS);
        session_data->js_data_lost_once = true;
        return;
    }

    if (http_header and http_header->is_external_js())
        normalizer->do_external(input, output, infractions, session_data, back);
    else
        normalizer->do_inline(input, output, infractions, session_data, back);
}

void HttpMsgBody::do_legacy_js_normalization(const Field& input, Field& output)
{
    if (!params->js_norm_param.normalize_javascript || source_id == SRC_CLIENT)
    {
        output.set(input);
        return;
    }

    params->js_norm_param.js_norm->do_legacy(input, output,
        transaction->get_infractions(source_id), session_data->events[source_id],
        params->js_norm_param.max_javascript_whitespaces);
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

        const uint64_t file_index = get_header(source_id)->get_file_cache_index();

        bool continue_processing_file = file_flows->file_process(p, file_index, file_data.start(),
            fp_length, session_data->file_octets[source_id], dir,
            get_header(source_id)->get_multi_file_processing_id(), file_position);
        if (continue_processing_file)
        {
            session_data->file_depth_remaining[source_id] -= fp_length;

            // With the first piece of the file we must provide the filename and URI
            if (front)
            {
                if (request != nullptr)
                {
                    const uint8_t* filename_buffer;
                    const uint8_t* uri_buffer;
                    uint32_t filename_length;
                    uint32_t uri_length;
                    get_file_info(dir, filename_buffer, filename_length, uri_buffer, uri_length);

                    continue_processing_file = file_flows->set_file_name(filename_buffer,
                        filename_length, 0,
                        get_header(source_id)->get_multi_file_processing_id(), uri_buffer,
                        uri_length);
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

// Parses out the filename and URI associated with this file.
// For the filename, if the message has a Content-Disposition header with a filename attribute,
// use that. Otherwise use the segment of the URI path after the last '/' but not including the
// query or fragment. For the uri, use the request raw uri. If there is no URI or nothing in the
// path after the last slash, the filename and uri buffers may be empty. The normalized URI is used.
void HttpMsgBody::get_file_info(FileDirection dir, const uint8_t*& filename_buffer,
    uint32_t& filename_length, const uint8_t*& uri_buffer, uint32_t& uri_length)
{
    filename_buffer = uri_buffer = nullptr;
    filename_length = uri_length = 0;
    HttpUri* http_uri = request->get_http_uri();

    // First handle the content-disposition case
    if (dir == FILE_UPLOAD)
    {
        const Field& cd_filename = get_header(source_id)->get_content_disposition_filename();
        if (cd_filename.length() > 0)
        {
            filename_buffer = cd_filename.start();
            filename_length = cd_filename.length();
        }
    }

    if (http_uri)
    {
        const Field& uri_field = http_uri->get_norm_classic();
        if (uri_field.length() > 0)
        {
            uri_buffer = uri_field.start();
            uri_length = uri_field.length();
        }

        // Don't overwrite the content-disposition filename
        if (filename_length > 0)
            return;

        const Field& path = http_uri->get_norm_path(); 
        if (path.length() > 0)
        {
            int last_slash_index = path.length() - 1;
            while (last_slash_index >= 0)
            {
                if (path.start()[last_slash_index] == '/')
                    break;
                last_slash_index--;
            }
            if (last_slash_index >= 0)
            {
                filename_length = (path.length() - (last_slash_index + 1));
                if (filename_length > 0)
                    filename_buffer = path.start() + last_slash_index + 1;
            }
        }
    }
}

const Field& HttpMsgBody::get_classic_client_body()
{
    return classic_normalize(detect_data, classic_client_body, false, params->uri_param);
}

const Field& HttpMsgBody::get_decomp_vba_data()
{
    if (decompressed_vba_data.length() != STAT_NOT_COMPUTE)
        return decompressed_vba_data;

    if (ole_data.length() <= 0)
    {
        decompressed_vba_data.set(STAT_NO_SOURCE);
        return decompressed_vba_data;
    }

    uint8_t* buf = nullptr;
    uint32_t buf_len = 0;

    VBA_DEBUG(vba_data_trace, DEFAULT_TRACE_OPTION_ID, TRACE_INFO_LEVEL, CURRENT_PACKET,
               "Found OLE file. Sending %d bytes for the processing.\n",
                ole_data.length());

    oleprocess(ole_data.start(), ole_data.length(), buf, buf_len);

    if (buf && buf_len)
        decompressed_vba_data.set(buf_len, buf, true);
    else
        decompressed_vba_data.set(STAT_NOT_PRESENT);

    return decompressed_vba_data;
}

const Field& HttpMsgBody::get_norm_js_data()
{
    if (norm_js_data.length() != STAT_NOT_COMPUTE)
        return norm_js_data;

    do_enhanced_js_normalization(decompressed_file_body, norm_js_data);

    if (norm_js_data.length() == STAT_NOT_COMPUTE)
        norm_js_data.set(STAT_NOT_PRESENT);

    return norm_js_data;
}

int32_t HttpMsgBody::get_publish_length() const
{
    return publish_length;
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

