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
// nhttp_msg_header.cc author Tom Peters <thopeter@cisco.com>

#include <cstring>
#include <cstdio>
#include <sys/types.h>

#include "utils/util.h"
#include "detection/detection_util.h"
#include "file_api/file_service.h"
#include "file_api/file_flows.h"

#include "nhttp_module.h"
#include "nhttp_api.h"
#include "nhttp_normalizers.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_header.h"

using namespace NHttpEnums;

NHttpMsgHeader::NHttpMsgHeader(const uint8_t* buffer, const uint16_t buf_size,
    NHttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const NHttpParaList* params_) :
    NHttpMsgHeadShared(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{
    transaction->set_header(this, source_id);
}

void NHttpMsgHeader::update_flow()
{
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;

    if (get_header_count(HEAD_CONTENT_LENGTH) > 1)
    {
        infractions += INF_MULTIPLE_CONTLEN;
        events.create_event(EVENT_MULTIPLE_CONTLEN);
    }
    if ((get_header_count(HEAD_CONTENT_LENGTH) > 0) &&
        (get_header_count(HEAD_TRANSFER_ENCODING) > 0))
    {
        infractions += INF_BOTH_CL_AND_TE;
        events.create_event(EVENT_BOTH_CL_AND_TE);
    }

    // The following logic to determine body type is by no means the last word on this topic.
    if (tcp_close)
    {
        session_data->half_reset(source_id);
        session_data->type_expected[source_id] = SEC_ABORT;
        return;
    }

    if ((source_id == SRC_SERVER) && ((status_code_num <= 199) || (status_code_num == 204) ||
        (status_code_num == 304)))
    {
        // No body allowed by RFC for these response codes. The message is over regardless of the
        // headers.
        if (get_header_count(HEAD_TRANSFER_ENCODING) > 0)
        {
            infractions += INF_BAD_CODE_BODY_HEADER;
            events.create_event(EVENT_BAD_CODE_BODY_HEADER);
        }
        if (get_header_count(HEAD_CONTENT_LENGTH) > 0)
        {
            if (norm_decimal_integer(get_header_value_norm(HEAD_CONTENT_LENGTH)) > 0)
            {
                infractions += INF_BAD_CODE_BODY_HEADER;
                events.create_event(EVENT_BAD_CODE_BODY_HEADER);
            }
        }
        session_data->half_reset(SRC_SERVER);
        return;
    }

    if ((source_id == SRC_SERVER) && (transaction->get_request() != nullptr) &&
        (transaction->get_request()->get_method_id() == METH_HEAD))
    {
        // No body allowed by RFC for response to HEAD method
        session_data->half_reset(SRC_SERVER);
        return;
    }

    // If there is a Transfer-Encoding header, see if the last of the encoded values is "chunked".
    if (get_header_value_norm(HEAD_TRANSFER_ENCODING).length > 0)
    {
        if (chunked_before_end(get_header_value_norm(HEAD_TRANSFER_ENCODING)))
        {
            infractions += INF_CHUNKED_BEFORE_END;
            events.create_event(EVENT_CHUNKED_BEFORE_END);
        }
        if (norm_last_token_code(get_header_value_norm(HEAD_TRANSFER_ENCODING),
            NHttpMsgHeadShared::trans_code_list) == TRANSCODE_CHUNKED)
        {
            // Chunked body
            session_data->type_expected[source_id] = SEC_BODY_CHUNK;
            NHttpModule::increment_peg_counts(PEG_CHUNKED);
            prepare_body();
            return;
        }
        else
        {
            infractions += INF_FINAL_NOT_CHUNKED;
            events.create_event(EVENT_FINAL_NOT_CHUNKED);
        }
    }

    // else because Transfer-Encoding header negates Content-Length header even if something was
    // wrong with Transfer-Encoding header.
    else if (get_header_value_norm(HEAD_CONTENT_LENGTH).length > 0)
    {
        const int64_t content_length =
            norm_decimal_integer(get_header_value_norm(HEAD_CONTENT_LENGTH));
        if (content_length > 0)
        {
            // Regular body
            session_data->type_expected[source_id] = SEC_BODY_CL;
            session_data->data_length[source_id] = content_length;
            prepare_body();
            return;
        }
        else if (content_length == 0)
        {
            // No body
            session_data->half_reset(source_id);
            return;
        }
        else
        {
            infractions += INF_BAD_HEADER_DATA;
            // Treat as if there was no Content-Length header (drop through)
        }
    }

    if (source_id == SRC_CLIENT)
    {
        // No body
        session_data->half_reset(source_id);
        return;
    }
    else
    {
        // Old-style response body runs to connection close
        session_data->type_expected[source_id] = SEC_BODY_OLD;
        prepare_body();
        return;
    }
}

// Common activities of preparing for upcoming regular body or chunked body
void NHttpMsgHeader::prepare_body()
{
    session_data->body_octets[source_id] = 0;
    const int64_t& depth = (source_id == SRC_CLIENT) ? params->request_depth :
        params->response_depth;
    session_data->detect_depth_remaining[source_id] = (depth != -1) ? depth : INT64_MAX;
    if (session_data->detect_depth_remaining[source_id] > 0)
    {
        // Depth must be positive because first body section must actually go to detection in order
        // to be the detection section
        detection_section = false;
    }
    setup_file_processing();
    setup_decompression();
    update_depth();
    session_data->infractions[source_id].reset();
    session_data->events[source_id].reset();
    if (source_id == SRC_CLIENT)
    {
        NHttpModule::increment_peg_counts(PEG_REQUEST_BODY);
    }
}

void NHttpMsgHeader::setup_file_processing()
{
    // FIXIT-M Bidirectional file processing is problematic so we don't do it. When the library
    // fully supports it remove the outer if statement that prevents it from being done.
    if (session_data->file_depth_remaining[1-source_id] <= 0)
    {
        if ((session_data->file_depth_remaining[source_id] = FileService::get_max_file_depth()) < 0)
        {
           session_data->file_depth_remaining[source_id] = 0;
           return;
        }

        if (source_id == SRC_CLIENT)
        {
            session_data->mime_state = new MimeSession(&decode_conf, &mime_conf);
        }
        else
        {
            FileFlows* file_flows = FileFlows::get_file_flows(flow);
            if (!file_flows)
                session_data->file_depth_remaining[source_id] = 0;
        }
    }
    else
    {
        session_data->file_depth_remaining[source_id] = 0;
    }
}

void NHttpMsgHeader::setup_decompression()
{
    if (!params->unzip)
        return;

    // FIXIT-M add support for compression in transfer encoding
    // FIXIT-M add support for multiple content encoding values
    const Field& norm_content_encoding = get_header_value_norm(HEAD_CONTENT_ENCODING);
    if (norm_content_encoding.length <= 0)
        return;

    const Contentcoding compress_code = (Contentcoding)norm_last_token_code(
        norm_content_encoding, NHttpMsgHeadShared::content_code_list);

    CompressId& compression = session_data->compression[source_id];

    if ((compress_code == CONTENTCODE_GZIP) || (compress_code == CONTENTCODE_X_GZIP))
        compression = CMP_GZIP;
    else if (compress_code == CONTENTCODE_DEFLATE)
        compression = CMP_DEFLATE;
    else
        return;

    session_data->compress_stream[source_id] = new z_stream;
    session_data->compress_stream[source_id]->zalloc = Z_NULL;
    session_data->compress_stream[source_id]->zfree = Z_NULL;
    session_data->compress_stream[source_id]->next_in = Z_NULL;
    session_data->compress_stream[source_id]->avail_in = 0;
    const int window_bits = (compression == CMP_GZIP) ? GZIP_WINDOW_BITS : DEFLATE_WINDOW_BITS;
    if (inflateInit2(session_data->compress_stream[source_id], window_bits) != Z_OK)
    {
        session_data->compression[source_id] = CMP_NONE;
        delete session_data->compress_stream[source_id];
        session_data->compress_stream[source_id] = nullptr;
    }
}

#ifdef REG_TEST
void NHttpMsgHeader::print_section(FILE* output)
{
    NHttpMsgSection::print_section_title(output, "header");
    NHttpMsgHeadShared::print_headers(output);
    get_classic_buffer(NHTTP_BUFFER_COOKIE, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_COOKIE-1]);
    get_classic_buffer(NHTTP_BUFFER_HEADER, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_HEADER-1]);
    get_classic_buffer(NHTTP_BUFFER_RAW_COOKIE, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_RAW_COOKIE-1]);
    get_classic_buffer(NHTTP_BUFFER_RAW_HEADER, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_RAW_HEADER-1]);
    NHttpMsgSection::print_section_wrapup(output);
}
#endif

