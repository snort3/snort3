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
// http_msg_body.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_body.h"

#include "decompress/file_olefile.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "helpers/buffer_data.h"
#include "js_norm/js_enum.h"
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
using namespace jsn;

#define CONTENT_BYTES "bytes"

extern THREAD_LOCAL const snort::Trace* js_trace;

static HttpInfractions decode_infs;

static void init_decode_infs()
{
    decode_infs += INF_UNKNOWN_ENCODING;
    decode_infs += INF_UNSUPPORTED_ENCODING;
    decode_infs += INF_STACKED_ENCODINGS;
    decode_infs += INF_CONTENT_ENCODING_CHUNKED;
    decode_infs += INF_GZIP_FAILURE;
    decode_infs += INF_GZIP_OVERRUN;
}

static int _init_decode_infs __attribute__((unused)) = (static_cast<void>(init_decode_infs()), 0);

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

void HttpMsgBody::publish(unsigned pub_id)
{
    if (publish_length <= 0)
        return;

    const int32_t& pub_depth_remaining = session_data->publish_depth_remaining[source_id];
    int32_t& publish_octets = session_data->publish_octets[source_id];
    const bool last_piece = (session_data->cutter[source_id] == nullptr) || tcp_close ||
        (pub_depth_remaining == 0);

    HttpRequestBodyEvent http_request_body_event(this, publish_octets, last_piece, session_data);

    DataBus::publish(pub_id, HttpEventIds::REQUEST_BODY, http_request_body_event, flow);
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
    session_data->detect_depth_remaining[source_id] -= detect_length;
    partial_detect_buffer = nullptr;
    partial_detect_length = 0;
    partial_js_detect_length = 0;
}

void HttpMsgBody::clean_partial(uint32_t& partial_inspected_octets, uint32_t& partial_detect_length,
    uint8_t*& partial_detect_buffer, uint32_t& partial_js_detect_length)
{
    body_octets += msg_text.length();
    partial_inspected_octets = session_data->partial_flush[source_id] ? msg_text.length() : 0;

    if (session_data->partial_flush[source_id])
        return;

    if (session_data->detect_depth_remaining[source_id] > 0)
    {
        delete[] partial_detect_buffer;
        const int32_t detect_length =
            (partial_js_detect_length <= session_data->detect_depth_remaining[source_id]) ?
            partial_js_detect_length : session_data->detect_depth_remaining[source_id];
        bookkeeping_regular_flush(partial_detect_length, partial_detect_buffer,
            partial_js_detect_length, detect_length);
    }
}

void HttpMsgBody::analyze()
{
    const int32_t raw_body_length =
        (msg_text.length() <= session_data->detect_depth_remaining[source_id]) ?
        msg_text.length() : session_data->detect_depth_remaining[source_id];

    if (raw_body_length > 0)
        raw_body.set(raw_body_length, msg_text.start());
    else
        raw_body.set(STAT_NO_SOURCE);

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

    if (session_data->mime_state[source_id])
    {
        // FIXIT-M this interface does not convey any indication of end of message body. If the
        // message body ends in the middle of a MIME message the partial file will not be flushed.

        Packet* p = DetectionEngine::get_current_packet();
        const uint8_t* const section_end = msg_text_new.start() + msg_text_new.length();
        const uint8_t* ptr = msg_text_new.start();
        MimeSession::AttachmentBuffer latest_attachment;

        if (session_data->partial_mime_bufs[source_id] != nullptr)
        {
            // Retrieve the attachment list stored during the partial inspection
            mime_bufs = session_data->partial_mime_bufs[source_id];
            session_data->partial_mime_bufs[source_id] = nullptr;
            last_attachment_complete = session_data->partial_mime_last_complete[source_id];
            session_data->partial_mime_last_complete[source_id] = true;

            if (!mime_bufs->empty())
                mime_bufs->front().file.set_accumulation(true);
        }
        else
            mime_bufs = new std::list<MimeBufs>;

        while (ptr < section_end)
        {
            // After process_mime_data(), ptr will point to the last byte processed in the current MIME part
            ptr = session_data->mime_state[source_id]->process_mime_data(p, ptr,
                (section_end - ptr), true, SNORT_FILE_POSITION_UNKNOWN);
            ptr++;

            latest_attachment = session_data->mime_state[source_id]->get_attachment();

            if (!latest_attachment.data)
            {
                last_attachment_complete = latest_attachment.finished;
                continue;
            }

            uint32_t attach_length;
            uint8_t* attach_buf;
            if (!last_attachment_complete)
            {
                assert(!mime_bufs->empty());
                // Remove the partial attachment from the list and replace it with an extended version
                const uint8_t* const old_buf = mime_bufs->back().file.start();
                const uint32_t old_length = mime_bufs->back().file.length();
                attach_length = old_length + latest_attachment.length;
                attach_buf = new uint8_t[attach_length];
                memcpy(attach_buf, old_buf, old_length);
                memcpy(attach_buf + old_length, latest_attachment.data, latest_attachment.length);
                mime_bufs->pop_back();
            }
            else
            {
                attach_length = latest_attachment.length;
                attach_buf = new uint8_t[attach_length];
                memcpy(attach_buf, latest_attachment.data, latest_attachment.length);
            }
            const BufferData& vba_buf = session_data->mime_state[source_id]->get_ole_buf();
            if (vba_buf.data_ptr() != nullptr)
            {
                uint8_t* my_vba_buf = new uint8_t[vba_buf.length()];
                memcpy(my_vba_buf, vba_buf.data_ptr(), vba_buf.length());
                mime_bufs->emplace_back(attach_length, attach_buf, true, vba_buf.length(), my_vba_buf, true);
            }
            else
                mime_bufs->emplace_back(attach_length, attach_buf, true, STAT_NOT_PRESENT, nullptr, false);

            mime_bufs->back().file.set_accumulation(!last_attachment_complete);
            last_attachment_complete = latest_attachment.finished;
        }

        detect_data.set(msg_text.length(), msg_text.start());
    }

    else if (session_data->file_depth_remaining[source_id] > 0 or
        session_data->detect_depth_remaining[source_id] > 0)
    {
        do_utf_decoding(msg_text_new, decoded_body);

        if (session_data->file_depth_remaining[source_id] > 0)
            do_file_processing(decoded_body);

        if (session_data->detect_depth_remaining[source_id] > 0)
        {
            do_file_decompression(decoded_body, decompressed_file_body);

            if (decompressed_file_body.length() > 0 and session_data->js_ctx[source_id])
                session_data->js_ctx[source_id]->ctx().tick();

            uint32_t& partial_detect_length = session_data->partial_detect_length[source_id];
            uint8_t*& partial_detect_buffer = session_data->partial_detect_buffer[source_id];
            uint32_t& partial_js_detect_length = session_data->partial_js_detect_length[source_id];

            if (partial_detect_length > 0)
            {
                detect_data.set_accumulation(true);
                norm_js_data.set_accumulation(true);
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
                // Partial inspections don't update detect_depth_remaining.
                // If there is no new data or same data will be sent to detection because
                // we already reached detect_depth, don't do another detection
                if ((int32_t)partial_js_detect_length == js_norm_body.length() ||
                    partial_js_detect_length >= session_data->detect_depth_remaining[source_id])
                {
                    clean_partial(partial_inspected_octets, partial_detect_length,
                        partial_detect_buffer, partial_js_detect_length);
                    return;
                }
            }
            else
                do_legacy_js_normalization(decompressed_file_body, js_norm_body);

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

            const uint64_t file_index = get_header(source_id)->get_multi_file_processing_id();
            set_file_data(const_cast<uint8_t*>(detect_data.start()),
                (unsigned)detect_data.length(), file_index, detect_data.is_accumulated());
        }
    }
    body_octets += msg_text.length();
    partial_inspected_octets = session_data->partial_flush[source_id] ? msg_text.length() : 0;
}

void HttpMsgBody::do_utf_decoding(const Field& input, Field& output)
{
    if ((session_data->utf_state[source_id] == nullptr) || (input.length() == 0))
    {
        output.set(input);
        return;
    }

    if (session_data->utf_state[source_id]->is_utf_encoding_present())
    {
        int bytes_copied;
        bool decoded;
        uint8_t* buffer = new uint8_t[input.length()];
        decoded = session_data->utf_state[source_id]->decode_utf(
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

    session_data->fd_state[source_id]->get_ole_data(ole_data_ptr, ole_len);

    if (ole_data_ptr)
    {
        ole_data.set(ole_len, ole_data_ptr, false);

        // Reset the ole data ptr once it is stored in msg body
        session_data->fd_state[source_id]->ole_data_reset();
    }
}

void HttpMsgBody::do_file_decompression(const Field& input, Field& output)
{
    if (session_data->fd_state[source_id] == nullptr)
    {
        output.set(input);
        return;
    }
    const uint32_t buffer_size = session_data->file_decomp_buffer_size_remaining[source_id];
    uint8_t* buffer = new uint8_t[buffer_size];
    session_data->fd_alert_context[source_id].infractions = transaction->get_infractions(source_id);
    session_data->fd_alert_context[source_id].events = session_data->events[source_id];
    session_data->fd_state[source_id]->Next_In = input.start();
    session_data->fd_state[source_id]->Avail_In = (uint32_t)input.length();
    session_data->fd_state[source_id]->Next_Out = buffer;
    session_data->fd_state[source_id]->Avail_Out = buffer_size;

    const fd_status_t status = File_Decomp(session_data->fd_state[source_id]);

    switch(status)
    {
    case File_Decomp_DecompError:
        File_Decomp_Alert(session_data->fd_state[source_id],
            session_data->fd_state[source_id]->Error_Event);
        // Fall through
    case File_Decomp_NoSig:
    case File_Decomp_Error:
        delete[] buffer;
        output.set(input);
        File_Decomp_StopFree(session_data->fd_state[source_id]);
        session_data->fd_state[source_id] = nullptr;
        break;
    case File_Decomp_BlockOut:
        add_infraction(INF_FILE_DECOMPR_OVERRUN);
        create_event(EVENT_FILE_DECOMPR_OVERRUN);
        // Fall through
    default:
        const uint32_t output_length = session_data->fd_state[source_id]->Next_Out - buffer;
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

void HttpMsgBody::do_legacy_js_normalization(const Field& input, Field& output)
{
    if (!params->js_norm_param.normalize_javascript || source_id == SRC_CLIENT)
    {
        output.set(input);
        return;
    }

    js_normalize(input, output, params,
        transaction->get_infractions(source_id), session_data->events[source_id]);
}

HttpJSNorm* HttpMsgBody::acquire_js_ctx()
{
    HttpJSNorm* js_ctx = session_data->js_ctx[source_id];

    if (js_ctx)
    {
        if (js_ctx->get_trans_num() == trans_num)
            return js_ctx;

        delete js_ctx;
        js_ctx = nullptr;
    }

    auto http_header = get_header(source_id);

    if (!http_header)
        return nullptr;

    JSNormConfig* jsn_config = get_inspection_policy()->jsn_config;

    switch(http_header->get_content_type())
    {
    case CT_APPLICATION_JAVASCRIPT:
    case CT_APPLICATION_ECMASCRIPT:
    case CT_APPLICATION_X_JAVASCRIPT:
    case CT_APPLICATION_X_ECMASCRIPT:
    case CT_TEXT_JAVASCRIPT:
    case CT_TEXT_JAVASCRIPT_1_0:
    case CT_TEXT_JAVASCRIPT_1_1:
    case CT_TEXT_JAVASCRIPT_1_2:
    case CT_TEXT_JAVASCRIPT_1_3:
    case CT_TEXT_JAVASCRIPT_1_4:
    case CT_TEXT_JAVASCRIPT_1_5:
    case CT_TEXT_ECMASCRIPT:
    case CT_TEXT_X_JAVASCRIPT:
    case CT_TEXT_X_ECMASCRIPT:
    case CT_TEXT_JSCRIPT:
    case CT_TEXT_LIVESCRIPT:
        // an external script should be processed from the beginning
        js_ctx = first_body ? new HttpExternalJSNorm(jsn_config, trans_num) : nullptr;
        break;

    case CT_APPLICATION_XHTML_XML:
    case CT_TEXT_HTML:
        js_ctx = new HttpInlineJSNorm(jsn_config, trans_num, params->js_norm_param.mpse_otag,
            params->js_norm_param.mpse_attr);
        break;

    case CT_APPLICATION_PDF:
        js_ctx = new HttpPDFJSNorm(jsn_config, trans_num);
        break;

    case CT_APPLICATION_OCTET_STREAM:
        js_ctx = first_body and HttpPDFJSNorm::is_pdf(decompressed_file_body.start(), decompressed_file_body.length()) ?
            new HttpPDFJSNorm(jsn_config, trans_num) : nullptr;
        break;
    }

    session_data->js_ctx[source_id] = js_ctx;
    return js_ctx;
}

HttpJSNorm* HttpMsgBody::acquire_js_ctx_mime()
{
    HttpJSNorm* js_ctx = session_data->js_ctx_mime[source_id];

    if (js_ctx)
    {
        if (js_ctx->get_trans_num() == trans_num)
            return js_ctx;

        delete js_ctx;
        js_ctx = nullptr;
    }

    JSNormConfig* jsn_config = get_inspection_policy()->jsn_config;
    js_ctx = HttpPDFJSNorm::is_pdf(decompressed_file_body.start(), decompressed_file_body.length()) ?
        new HttpPDFJSNorm(jsn_config, trans_num) : nullptr;

    session_data->js_ctx_mime[source_id] = js_ctx;
    return js_ctx;
}

void HttpMsgBody::clear_js_ctx_mime()
{
    delete session_data->js_ctx_mime[source_id];
    session_data->js_ctx_mime[source_id] = nullptr;
}

static FilePosition find_range_file_pos(const std::string& hdr_content, bool front, bool back)
{
    // content range format: <unit> <range_start>-<range_end>/<file_size>

    size_t processed = 0;

    for (; processed < hdr_content.length() and hdr_content[processed] == ' '; ++processed);

    if (processed == hdr_content.length())
        return SNORT_FILE_POSITION_UNKNOWN;

    // currently only single ranges with bytes unit are supported
    if (hdr_content.compare(processed, sizeof(CONTENT_BYTES) - 1, CONTENT_BYTES) != 0)
        return SNORT_FILE_POSITION_UNKNOWN;

    processed += sizeof(CONTENT_BYTES) - 1;

    for (; processed < hdr_content.length() and hdr_content[processed] == ' '; ++processed);

    if (processed == hdr_content.length() or !isdigit(hdr_content[processed]))
        return SNORT_FILE_POSITION_UNKNOWN;

    size_t dash_pos = hdr_content.find('-', processed);

    if (dash_pos == hdr_content.npos or dash_pos == processed)
        return SNORT_FILE_POSITION_UNKNOWN;

    size_t slash_pos = hdr_content.find('/', dash_pos);

    if (slash_pos == hdr_content.npos)
        return SNORT_FILE_POSITION_UNKNOWN;

    char *end_ptr = nullptr;

    unsigned long range_start = SnortStrtoul(hdr_content.c_str() + processed, &end_ptr, 10);

    if (errno or end_ptr != hdr_content.c_str() + dash_pos)
        return SNORT_FILE_POSITION_UNKNOWN;

    if (range_start != 0)
        return SNORT_FILE_MIDDLE;

    unsigned long range_end = SnortStrtoul(hdr_content.c_str() + dash_pos + 1, &end_ptr, 10);

    if (errno or range_end == 0 or end_ptr != hdr_content.c_str() + slash_pos)
        return SNORT_FILE_POSITION_UNKNOWN;

    unsigned long file_size = 1;

    // asterisk - complete file length is unknown
    if (hdr_content[slash_pos + 1] != '*')
    {
        file_size = SnortStrtoul(hdr_content.c_str() + slash_pos + 1, &end_ptr, 10);

        if (errno or range_end >= file_size or end_ptr > hdr_content.c_str() + hdr_content.length())
            return SNORT_FILE_POSITION_UNKNOWN;
    }

    if (range_end == file_size - 1)
    {
        if (front && back)
            return SNORT_FILE_FULL;
        else if (front)
            return SNORT_FILE_START;
        else if (back)
            return SNORT_FILE_END;
        else
            return SNORT_FILE_MIDDLE;
    }

    if (front && back)
        return SNORT_FILE_MIDDLE;
    else if (front)
        return SNORT_FILE_START;
    else
        return SNORT_FILE_MIDDLE;
}


void HttpMsgBody::do_file_processing(const Field& file_data)
{
    // Using the trick that cutter is deleted when regular or chunked body is complete
    Packet* p = DetectionEngine::get_current_packet();
    FilePosition file_position = SNORT_FILE_POSITION_UNKNOWN;

    const bool front = (body_octets == 0) &&
        (session_data->partial_inspected_octets[source_id] == 0);
    const bool back = (session_data->cutter[source_id] == nullptr) || tcp_close;

    if (session_data->status_code_num != 206 or source_id != SRC_SERVER)
    {
        if (front && back)
            file_position = SNORT_FILE_FULL;
        else if (front)
            file_position = SNORT_FILE_START;
        else if (back)
            file_position = SNORT_FILE_END;
        else
            file_position = SNORT_FILE_MIDDLE;

        // Chunked body with nothing but the zero length chunk?
        if (front && (file_data.length() == 0))
            return;
    }
    else
    {
        const Field& range_hdr = get_header(SRC_SERVER)->get_header_value_raw(HEAD_CONTENT_RANGE);

        if (range_hdr.length() <= 0)
            return;

        file_position = find_range_file_pos(std::string((const char*)range_hdr.start(), range_hdr.length()),
            front, back);

        if (file_position == SNORT_FILE_POSITION_UNKNOWN)
            return;
    }

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

bool HttpMsgBody::run_detection(snort::Packet* p)
{
    if ((p == nullptr) || !detection_required())
        return false;
    if ((mime_bufs != nullptr) && !mime_bufs->empty())
    {
        HttpJSNorm* js_ctx_tmp = nullptr;
        auto mb = mime_bufs->cbegin();
        uint32_t mime_bufs_size = mime_bufs->size();

        for (uint32_t count = 0; (count < params->max_mime_attach) && (mb != mime_bufs->cend());
            ++count, ++mb)
        {
            bool is_last_attachment = ((count + 1 == mime_bufs_size) ||
                (count + 1 == params->max_mime_attach));
            const uint64_t idx = get_header(source_id)->get_multi_file_processing_id();
            set_file_data(mb->file.start(), mb->file.length(), idx,
                count or mb->file.is_accumulated(),
                std::next(mb) != mime_bufs->end() or last_attachment_complete);
            if (mb->vba.length() > 0)
                ole_data.set(mb->vba.length(), mb->vba.start());
            decompressed_file_body.reset();
            decompressed_file_body.set(mb->file.length(), mb->file.start());

            js_ctx_tmp = session_data->js_ctx[source_id];
            session_data->js_ctx[source_id] = acquire_js_ctx_mime();

            // When multiple attachments appear in a single TCP segment,
            // the detection engine caches the results of the rule options after
            // evaluating on the first call. Setting this flag stops the caching.
            p->packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;

            DetectionEngine::detect(p);

            if (!is_last_attachment || last_attachment_complete)
                clear_js_ctx_mime();

            session_data->js_ctx[source_id] = js_ctx_tmp;

            ole_data.reset();
            decompressed_vba_data.reset();
            decompressed_file_body.reset();
        }
        if (mb != mime_bufs->cend())
        {
            // More MIME attachments than we have resources to inspect
            HttpModule::increment_peg_counts(PEG_SKIP_MIME_ATTACH);
        }
    }
    else
        DetectionEngine::detect(p);
    return true;
}

void HttpMsgBody::clear()
{
    if (session_data->partial_flush[source_id])
    {
        // Stash the MIME file attachments for use in full inspection
        session_data->partial_mime_bufs[source_id] = mime_bufs;
        mime_bufs = nullptr;
        session_data->partial_mime_last_complete[source_id] = last_attachment_complete;
    }

    HttpMsgSection::clear();
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

    auto infractions = this->transaction->get_infractions(source_id);

    if (*infractions & decode_infs)
    {
        norm_js_data.set(STAT_NO_SOURCE);
        return norm_js_data;
    }

    int src_len = decompressed_file_body.length();

    if (src_len <= 0)
    {
        norm_js_data.set(STAT_NO_SOURCE);
        return norm_js_data;
    }

    auto jsn = acquire_js_ctx();

    if (!jsn)
    {
        norm_js_data.set(STAT_NO_SOURCE);
        return norm_js_data;
    }

    const void* src = decompressed_file_body.start();
    const void* dst = nullptr;
    size_t dst_len = HttpCommon::STAT_NOT_PRESENT;
    bool back = !session_data->partial_flush[source_id];

    jsn->link(src, session_data->events[source_id], infractions);
    jsn->ctx().normalize(src, src_len, dst, dst_len);

    debug_logf(4, js_trace, TRACE_PROC, DetectionEngine::get_current_packet(),
        "input data was %s\n", back ? "last one in PDU" : "a part of PDU");

    if (!dst or !dst_len)
        norm_js_data.set(STAT_NOT_PRESENT);
    else
    {
        if (back)
            jsn->ctx().flush_data(dst, dst_len);
        norm_js_data.set(dst_len, (const uint8_t*)dst, back);
    }

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
    if ((mime_bufs != nullptr) && !mime_bufs->empty())
        for (MimeBufs& mb : *mime_bufs)
        {
            mb.file.print(output, "MIME data");
            mb.vba.print(output, "MIME OLE data");
            if (mb.vba.length() > 0)
                ole_data.set(mb.vba.length(), mb.vba.start());
            get_decomp_vba_data().print(output, "MIME Decompressed VBA data");
            ole_data.reset();
            decompressed_vba_data.reset();
        }
    else
    {
        ole_data.print(output, "OLE data");
        get_decomp_vba_data().print(output, "Decompressed VBA data");
    }
    get_classic_buffer(HTTP_BUFFER_CLIENT_BODY, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_CLIENT_BODY-1]);
    get_classic_buffer(HTTP_BUFFER_RAW_BODY, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_BODY-1]);

    HttpMsgSection::print_section_wrapup(output);
}
#endif
