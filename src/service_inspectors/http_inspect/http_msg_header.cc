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
// http_msg_header.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_header.h"

#include "decompress/file_decomp.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "http_api.h"
#include "http_msg_request.h"
#include "http_msg_body.h"
#include "pub_sub/http_events.h"
#include "sfip/sf_ip.h"

using namespace snort;
using namespace HttpEnums;

HttpMsgHeader::HttpMsgHeader(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgHeadShared(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{
    transaction->set_header(this, source_id);
}

void HttpMsgHeader::publish()
{
    HttpEvent http_event(this);

    const char* key = (source_id == SRC_CLIENT) ?
        HTTP_REQUEST_HEADER_EVENT_KEY : HTTP_RESPONSE_HEADER_EVENT_KEY; 

    DataBus::publish(key, http_event, flow);
}

const Field& HttpMsgHeader::get_true_ip()
{
    if (true_ip.length() != STAT_NOT_COMPUTE)
        return true_ip;

    const Field* header_to_use;
    const Field& xff = get_header_value_norm(HEAD_X_FORWARDED_FOR);
    if (xff.length() > 0)
        header_to_use = &xff;
    else
    {
        const Field& tcip = get_header_value_norm(HEAD_TRUE_CLIENT_IP);
        if (tcip.length() > 0)
            header_to_use = &tcip;
        else
        {
            true_ip.set(STAT_NOT_PRESENT);
            return true_ip;
        }
    }

    // This is potentially a comma-separated list of IP addresses. Take the last one in the list.
    // Since this is a normalized header field any whitespace will be an actual space.
    int32_t length;
    for (length = 0; length < header_to_use->length(); length++)
    {
        if (is_sp_comma[header_to_use->start()[header_to_use->length() - length - 1]])
            break;
    }

    true_ip.set(length, header_to_use->start() + (header_to_use->length() - length));
    return true_ip;
}

const Field& HttpMsgHeader::get_true_ip_addr()
{
    if (true_ip_addr.length() != STAT_NOT_COMPUTE)
        return true_ip_addr;

    const Field& true_ip = get_true_ip();
    if (true_ip.length() <= 0)
    {
        true_ip_addr.set(STAT_NOT_PRESENT);
        return true_ip_addr;
    }

    // Need a temporary copy so we can add null termination
    uint8_t* addr_str = new uint8_t[true_ip.length()+1];
    memcpy(addr_str, true_ip.start(), true_ip.length());
    addr_str[true_ip.length()] = '\0';

    SfIp tmp_sfip;
    const SfIpRet status = tmp_sfip.set((char*)addr_str);
    delete[] addr_str;
    if (status != SFIP_SUCCESS)
    {
        true_ip_addr.set(STAT_PROBLEMATIC);
    }
    else
    {
        const size_t addr_length = (tmp_sfip.is_ip6() ? 4 : 1);
        uint32_t* const addr_buf = new uint32_t[addr_length];
        memcpy(addr_buf, tmp_sfip.get_ptr(), addr_length * sizeof(uint32_t));
        true_ip_addr.set(addr_length * sizeof(uint32_t), (uint8_t*)addr_buf, true);
    }
    return true_ip_addr;
}

void HttpMsgHeader::gen_events()
{
    if ((get_header_count(HEAD_CONTENT_LENGTH) > 0) &&
        (get_header_count(HEAD_TRANSFER_ENCODING) > 0))
    {
        add_infraction(INF_BOTH_CL_AND_TE);
        create_event(EVENT_BOTH_CL_AND_TE);
    }
    // Content-Transfer-Encoding is a MIME header not sanctioned by HTTP. Which may not prevent
    // some clients from recognizing it and applying a decoding that Snort does not expect.
    if (get_header_count(HEAD_CONTENT_TRANSFER_ENCODING) > 0)
    {
        add_infraction(INF_CTE_HEADER);
        create_event(EVENT_CTE_HEADER);
    }
}

void HttpMsgHeader::update_flow()
{
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;

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
            add_infraction(INF_BAD_CODE_BODY_HEADER);
            create_event(EVENT_BAD_CODE_BODY_HEADER);
        }
        if (get_header_count(HEAD_CONTENT_LENGTH) > 0)
        {
            if (norm_decimal_integer(get_header_value_norm(HEAD_CONTENT_LENGTH)) > 0)
            {
                add_infraction(INF_BAD_CODE_BODY_HEADER);
                create_event(EVENT_BAD_CODE_BODY_HEADER);
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

    const Field& te_header = get_header_value_norm(HEAD_TRANSFER_ENCODING);
    if ((te_header.length() > 0) && (version_id == VERS_1_0))
    {
        // HTTP 1.0 should not be chunked and many browsers will ignore the TE header
        add_infraction(INF_CHUNKED_ONE_POINT_ZERO);
        create_event(EVENT_CHUNKED_ONE_POINT_ZERO);
    }
    if ((te_header.length() > 0) && (version_id != VERS_1_0))
    {
        // If there is a Transfer-Encoding header, it should be "chunked" without any other
        // encodings being listed. The RFC allows other encodings to come before chunked but
        // no one does this in real life.
        const int CHUNKED_SIZE = 7;
        bool is_chunked = false;

        if ((te_header.length() == CHUNKED_SIZE) &&
            !memcmp(te_header.start(), "chunked", CHUNKED_SIZE))
        {
            is_chunked = true;
        }
        else if ((te_header.length() > CHUNKED_SIZE) &&
            !memcmp(te_header.start() + (te_header.length() - (CHUNKED_SIZE+1)),
                ",chunked", CHUNKED_SIZE+1))
        {
            add_infraction(INF_PADDED_TE_HEADER);
            create_event(EVENT_PADDED_TE_HEADER);
            is_chunked = true;
        }

        if (is_chunked)
        {
            session_data->type_expected[source_id] = SEC_BODY_CHUNK;
            HttpModule::increment_peg_counts(PEG_CHUNKED);
            prepare_body();
            return;
        }
        else
        {
            add_infraction(INF_BAD_TE_HEADER);
            create_event(EVENT_BAD_TE_HEADER);
        }
    }

    // else because Transfer-Encoding header negates Content-Length header even if something was
    // wrong with Transfer-Encoding header. However a Transfer-Encoding header in a 1.0 message
    // does not negate the Content-Length header.
    // FIXIT-L the following can be zero, need an alert for empty CL header value
    else if (get_header_value_norm(HEAD_CONTENT_LENGTH).length() > 0)
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
            if (get_header_count(HEAD_EXPECT) > 0)
            {
                add_infraction(INF_EXPECT_WITHOUT_BODY_CL0);
                create_event(EVENT_EXPECT_WITHOUT_BODY);
            }
            session_data->half_reset(source_id);
            return;
        }
        else
        {
            add_infraction(INF_BAD_CONTENT_LENGTH);
            create_event(EVENT_BAD_CONTENT_LENGTH);
            // Treat as if there was no Content-Length header (drop through)
        }
    }

    if (source_id == SRC_CLIENT)
    {
        // No body
        if ((method_id == METH_POST) || (method_id == METH_PUT))
        {
            // Despite the name of this event, we assume for parsing purposes that this POST or PUT
            // does not have a body rather than running to connection close. Obviously that is just
            // an assumption.
            add_infraction(INF_POST_WO_BODY);
            create_event(EVENT_UNBOUNDED_POST);
        }
        if (get_header_count(HEAD_EXPECT) > 0)
        {
            add_infraction(INF_EXPECT_WITHOUT_BODY_NO_CL);
            create_event(EVENT_EXPECT_WITHOUT_BODY);
        }
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
void HttpMsgHeader::prepare_body()
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
    setup_encoding_decompression();
    setup_utf_decoding();
    setup_pdf_swf_decompression();
    update_depth();
    if (source_id == SRC_CLIENT)
    {
        HttpModule::increment_peg_counts(PEG_REQUEST_BODY);
    }
}

void HttpMsgHeader::setup_file_processing()
{
    // FIXIT-M Bidirectional file processing is problematic so we don't do it. When the library
    // fully supports it remove the outer if statement that prevents it from being done.
    if (session_data->file_depth_remaining[1-source_id] <= 0)
    {
        if ((session_data->file_depth_remaining[source_id] = FileService::get_max_file_depth())
             < 0)
        {
           session_data->file_depth_remaining[source_id] = 0;
           return;
        }

        // Do we meet all the conditions for MIME file processing?
        if (source_id == SRC_CLIENT)
        {
            const Field& content_type = get_header_value_raw(HEAD_CONTENT_TYPE);
            if (content_type.length() > 0)
            {
                if (boundary_present(content_type))
                {
                    session_data->mime_state[source_id] =
                        new MimeSession(&decode_conf, &mime_conf);
                    // Show file processing the Content-Type header as if it were regular data.
                    // This will enable it to find the boundary string.
                    // FIXIT-L develop a proper interface for passing the boundary string.
                    // This interface is a leftover from when OHI pushed whole messages through
                    // this interface.
                    session_data->mime_state[source_id]->process_mime_data(flow,
                        content_type.start(), content_type.length(), true,
                        SNORT_FILE_POSITION_UNKNOWN);
                    session_data->mime_state[source_id]->process_mime_data(flow,
                        (const uint8_t*)"\r\n", 2, true, SNORT_FILE_POSITION_UNKNOWN);
                }
            }
        }

        // Otherwise do regular file processing
        if (session_data->mime_state[source_id] == nullptr)
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

void HttpMsgHeader::setup_encoding_decompression()
{
    if (!params->unzip)
        return;

    CompressId& compression = session_data->compression[source_id];

    // Search the Content-Encoding header to find the type of compression used. We detect and alert
    // on multiple layers of compression but we only decompress the outermost layer. Thus the last
    // encoding in the Content-Encoding header is the one we use. If we don't recognize or support
    // the last encoding we won't do anything.

    const Field& norm_content_encoding = get_header_value_norm(HEAD_CONTENT_ENCODING);
    int32_t cont_offset = 0;
    while (norm_content_encoding.length() > cont_offset)
    {
        const Contentcoding content_code = (Contentcoding)get_next_code(norm_content_encoding,
            cont_offset, HttpMsgHeadShared::content_code_list);
        if ((compression != CMP_NONE) && (content_code != CONTENTCODE_IDENTITY))
        {
            add_infraction(INF_STACKED_ENCODINGS);
            create_event(EVENT_STACKED_ENCODINGS);
            compression = CMP_NONE;
        }
        switch (content_code)
        {
        case CONTENTCODE_GZIP:
        case CONTENTCODE_X_GZIP:
            compression = CMP_GZIP;
            break;
        case CONTENTCODE_DEFLATE:
            compression = CMP_DEFLATE;
            break;
        case CONTENTCODE_IDENTITY:
            break;
        case CONTENTCODE_CHUNKED:
            add_infraction(INF_CONTENT_ENCODING_CHUNKED);
            create_event(EVENT_CONTENT_ENCODING_CHUNKED);
            break;
        case CONTENTCODE__OTHER:
            // The ones we never heard of
            add_infraction(INF_UNKNOWN_ENCODING);
            create_event(EVENT_UNKNOWN_ENCODING);
            break;
        default:
            // The ones we know by name but don't support
            add_infraction(INF_UNSUPPORTED_ENCODING);
            create_event(EVENT_UNSUPPORTED_ENCODING);
            break;
        }
    }

    if (compression == CMP_NONE)
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

void HttpMsgHeader::setup_utf_decoding()
{
    if (!params->normalize_utf || source_id == SRC_CLIENT )
        return;

    Field last_token;
    CharsetCode charset_code;

    const Field& norm_content_type = get_header_value_norm(HEAD_CONTENT_TYPE);
    if (norm_content_type.length() <= 0)
        return;

    get_last_token(norm_content_type, last_token, ';');

    // No semicolon in the Content-Type header
    if ( last_token.length() == norm_content_type.length() )
    {
        if (SnortStrnStr((const char*)norm_content_type.start(), norm_content_type.length(),
            "text"))
        {
            charset_code = CHARSET_UNKNOWN;
        }
        else
            return;
    }
    else
    {
        charset_code = (CharsetCode)str_to_code(last_token.start(), last_token.length(),
            HttpMsgHeadShared::charset_code_list);

        if( charset_code == CHARSET_OTHER )
        {
            charset_code = (CharsetCode)substr_to_code(last_token.start(), last_token.length(),
                HttpMsgHeadShared::charset_code_opt_list);

            if ( charset_code != CHARSET_UNKNOWN )
                return;
        }
        else if ( charset_code == CHARSET_UTF7 )
        {
            add_infraction(INF_UTF7);
            create_event(EVENT_UTF7);
        }
    }

    session_data->utf_state = new UtfDecodeSession();
    session_data->utf_state->set_decode_utf_state_charset(charset_code);
}

void HttpMsgHeader::setup_pdf_swf_decompression()
{
    if (source_id == SRC_CLIENT || (!params->decompress_pdf && !params->decompress_swf))
        return;

    session_data->fd_state = File_Decomp_New();
    session_data->fd_state->Modes =
        (params->decompress_pdf ? FILE_PDF_DEFL_BIT : 0) |
        (params->decompress_swf ? (FILE_SWF_ZLIB_BIT | FILE_SWF_LZMA_BIT) : 0);
    session_data->fd_state->Alert_Callback = HttpMsgBody::fd_event_callback;
    session_data->fd_state->Alert_Context = &session_data->fd_alert_context;
    session_data->fd_state->Compr_Depth = 0;
    session_data->fd_state->Decompr_Depth = 0;

    (void)File_Decomp_Init(session_data->fd_state);
}

#ifdef REG_TEST
void HttpMsgHeader::print_section(FILE* output)
{
    HttpMsgSection::print_section_title(output, "header");
    HttpMsgHeadShared::print_headers(output);
    get_classic_buffer(HTTP_BUFFER_COOKIE, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_COOKIE-1]);
    get_classic_buffer(HTTP_BUFFER_HEADER, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_HEADER-1]);
    if (source_id == SRC_CLIENT)
    {
        get_classic_buffer(HTTP_BUFFER_TRUE_IP, 0, 0).print(output,
            HttpApi::classic_buffer_names[HTTP_BUFFER_TRUE_IP-1]);
    }
    get_classic_buffer(HTTP_BUFFER_RAW_COOKIE, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_COOKIE-1]);
    get_classic_buffer(HTTP_BUFFER_RAW_HEADER, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_HEADER-1]);
    HttpMsgSection::print_section_wrapup(output);
}
#endif

