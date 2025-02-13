//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <cassert>

#include "decompress/file_decomp.h"
#include "file_api/file_flows.h"
#include "file_api/file_service.h"
#include "hash/hash_key_operations.h"
#include "pub_sub/http_events.h"
#include "pub_sub/http_request_body_event.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "sfip/sf_ip.h"

#include "http_api.h"
#include "http_common.h"
#include "http_enum.h"
#include "http_inspect.h"
#include "http_js_norm.h"
#include "http_msg_request.h"
#include "http_msg_body.h"
#include "http_normalizers.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

HttpMsgHeader::HttpMsgHeader(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgHeadShared(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{
    transaction->set_header(this, source_id);
    get_related_sections();
}

void HttpMsgHeader::publish(unsigned pub_id)
{
    const int64_t stream_id = session_data->get_hx_stream_id();

    HttpEvent http_header_event(this, session_data->for_httpx, stream_id);

    unsigned evid = (source_id == SRC_CLIENT) ?
        HttpEventIds::REQUEST_HEADER : HttpEventIds::RESPONSE_HEADER;

    DataBus::publish(pub_id, evid, http_header_event, flow);
}

const Field& HttpMsgHeader::get_true_ip()
{
    if (true_ip.length() != STAT_NOT_COMPUTE)
        return true_ip;

    const Field* header_to_use = nullptr;

    for (int idx = 0; params->xff_headers[idx].code; idx++)
    {
        const Field& xff = get_header_value_norm((HeaderId)params->xff_headers[idx].code);
        if (xff.length() > 0)
        {
            header_to_use = &xff;
            break;
        }
    }

    if (!header_to_use)
    {
        true_ip.set(STAT_NOT_PRESENT);
        return true_ip;
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

    const Field& tmp_true_ip = get_true_ip();
    if (tmp_true_ip.length() <= 0)
    {
        true_ip_addr.set(STAT_NOT_PRESENT);
        return true_ip_addr;
    }

    // Need a temporary copy so we can add null termination
    uint8_t* addr_str = new uint8_t[true_ip.length()+1];
    memcpy(addr_str, true_ip.start(), true_ip.length());
    addr_str[true_ip.length()] = '\0';

    SfIp tmp_sfip;

    /* remove port number from ip address */
    char* colon_port = strrchr((char*)addr_str, ':');
    if (colon_port && (strpbrk((char*)addr_str, "[.")))
        *colon_port = '\0';

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

int32_t HttpMsgHeader::get_num_cookies()
{
    if (num_cookies != STAT_NOT_COMPUTE)
        return num_cookies;

    num_cookies = 0;
    for (int j=0; j < num_headers; j++)
    {
        if (header_name_id[j] == HEAD_SET_COOKIE)
            num_cookies++;
        else if (header_name_id[j] == HEAD_COOKIE)
        {
            const uint8_t* lim = header_line[j].start() + header_line[j].length();
            for (const uint8_t* p = header_line[j].start();  p < lim; p++)
                if (*p == ';')
                    num_cookies++;
            num_cookies++;
        }
    }

    return num_cookies;
}

 std::string HttpMsgHeader::get_host_header_field() const
 {
    if (host_name.length() > STAT_EMPTY_STRING)
        return std::string((const char*)host_name.start(), host_name.length());

    return "";
 }

void HttpMsgHeader::gen_events()
{
    if ((get_header_count(HEAD_CONTENT_LENGTH) > 0) &&
        (get_header_count(HEAD_TRANSFER_ENCODING) > 0) && !session_data->for_httpx)
    {
        add_infraction(INF_BOTH_CL_AND_TE);
        create_event(EVENT_BOTH_CL_AND_TE);
    }

    // Force inspection of the Host field
    if (source_id == SRC_CLIENT)
        host_name.set(get_header_value_norm(HEAD_HOST));

    // Host header value too long
    if ((params->maximum_host_length != -1) && (source_id == SRC_CLIENT))
    {
        if (get_all_header_values_raw(HEAD_HOST).length() > params->maximum_host_length)
        {
            add_infraction(INF_LONG_HOST_VALUE);
            create_event(EVENT_LONG_HOSTNAME);
        }
    }

    // Content-Transfer-Encoding is a MIME header not sanctioned by HTTP. Which may not prevent
    // some clients from recognizing it and applying a decoding that Snort does not expect.
    if (get_header_count(HEAD_CONTENT_TRANSFER_ENCODING) > 0)
    {
        add_infraction(INF_CTE_HEADER);
        create_event(EVENT_CTE_HEADER);
    }

    // We don't support HTTP/1 to HTTP/2 upgrade and we alert on any attempt to do it
    if (get_header_count(HEAD_HTTP2_SETTINGS) > 0)
    {
        add_infraction(INF_HTTP2_SETTINGS);
        if (source_id == SRC_CLIENT)
            create_event(EVENT_HTTP2_UPGRADE_REQUEST);
        else
            create_event(EVENT_HTTP2_UPGRADE_RESPONSE);
    }
    if ((get_header_count(HEAD_UPGRADE) > 0) &&
        ((source_id == SRC_CLIENT) || (status_code_num == 101)))
    {
        const Field& up_header = get_header_value_norm(HEAD_UPGRADE);
        int32_t consumed = 0;
        do
        {
            const int32_t upgrade = get_code_from_token_list(up_header.start(), up_header.length(),
                consumed, upgrade_list);
            if ((upgrade == UP_H2C) || (upgrade == UP_H2) || (upgrade == UP_HTTP20)) //FIXIT-E: Handle upgrade for h3
            {
                add_infraction(INF_UPGRADE_HEADER_HTTP2);
                if (source_id == SRC_CLIENT)
                    create_event(EVENT_HTTP2_UPGRADE_REQUEST);
                else
                    create_event(EVENT_HTTP2_UPGRADE_RESPONSE);
                break;
            }
        }
        while (consumed != -1);
    }

    // Check for an empty value in Accept-Encoding (two consecutive commas)
    if (has_consecutive_commas(get_header_value_norm(HEAD_ACCEPT_ENCODING)))
    {
        add_infraction(INF_ACCEPT_ENCODING_CONSECUTIVE_COMMAS);
        create_event(EVENT_ACCEPT_ENCODING_CONSECUTIVE_COMMAS);
    }

}

void HttpMsgHeader::update_flow()
{
    // The following logic to determine body type is by no means the last word on this topic.
    if (tcp_close)
    {
        session_data->half_reset(source_id);
        session_data->type_expected[source_id] = SEC_ABORT;
        return;
    }

    if ((source_id == SRC_SERVER) && request && (request->get_method_id() == METH_CONNECT) &&
        !session_data->for_httpx)
    {
        // Successful CONNECT responses (2XX) switch to tunneled traffic immediately following the
        // header. Transfer-Encoding and Content-Length headers are not allowed in successful
        // responses by the RFC.
        if((trans_num > session_data->last_connect_trans_w_early_traffic) &&
            ((status_code_num >= 200) && (status_code_num < 300)))
        {
            if ((get_header_count(HEAD_TRANSFER_ENCODING) > 0))
            {
                add_infraction(INF_200_CONNECT_RESP_WITH_TE);
                create_event(EVENT_200_CONNECT_RESP_WITH_TE);
            }
            if (get_header_count(HEAD_CONTENT_LENGTH) > 0)
            {
                add_infraction(INF_200_CONNECT_RESP_WITH_CL);
                create_event(EVENT_200_CONNECT_RESP_WITH_CL);
            }

            // FIXIT-E This case addresses the scenario where Snort sees a success response to a
            // CONNECT request before the request message is complete. Currently this will trigger
            // an alert then proceed to cutover as usual, meaning the remaining request message will
            // be processed as part of the tunnel session. There may be a better solution.
            if (session_data->type_expected[SRC_CLIENT] != SEC_REQUEST)
            {
                add_infraction(INF_EARLY_CONNECT_RESPONSE);
                create_event(EVENT_EARLY_CONNECT_RESPONSE);
            }
            session_data->cutover_on_clear = true;
            HttpModule::increment_peg_counts(PEG_CUTOVERS);
            if (session_data->ssl_search_abandoned)
                HttpModule::increment_peg_counts(PEG_SSL_SEARCH_ABND_EARLY);
#ifdef REG_TEST
            if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
            {
                fprintf(HttpTestManager::get_output_file(), "2XX CONNECT response triggered flow "
                    "cutover to wizard\n");
            }
#endif

            return;
        }
        if ((status_code_num >= 100) && (status_code_num < 200))
        {
            add_infraction(INF_100_CONNECT_RESP);
            create_event(EVENT_100_CONNECT_RESP);
        }
    }

    if ((source_id == SRC_SERVER) &&
        ((100 <= status_code_num && status_code_num <= 199) || (status_code_num == 204) ||
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

    if ((source_id == SRC_SERVER) && (request != nullptr) &&
        (request->get_method_id() == METH_HEAD))
    {
        // No body allowed by RFC for response to HEAD method
        session_data->half_reset(SRC_SERVER);
        return;
    }

    const Field& te_header = get_header_value_norm(HEAD_TRANSFER_ENCODING);

    if (session_data->for_httpx)
    {
        // The only transfer-encoding header we should see for HTTP/2 traffic is "identity"
        if (te_header.length() > 0)
        {
            int32_t consumed = 0;
            if ((get_code_from_token_list(te_header.start(), te_header.length(), consumed,
                transfer_encoding_list) != TE_IDENTITY) || (consumed != -1))
            {
                add_infraction(INF_H2_NON_IDENTITY_TE);
                create_event(EVENT_H2_NON_IDENTITY_TE);
            }
        }
        if (get_header_value_norm(HEAD_CONTENT_LENGTH).length() > 0)
        {
            const int64_t content_length =
                norm_decimal_integer(get_header_value_norm(HEAD_CONTENT_LENGTH));
            if (content_length >= 0)
                session_data->data_length[source_id] = content_length;
            else
            {
                add_infraction(INF_BAD_CONTENT_LENGTH);
                create_event(EVENT_BAD_CONTENT_LENGTH);
            }
        }
        if (session_data->hx_body_state[source_id] == HX_BODY_NO_BODY)
            session_data->half_reset(source_id);
        else
        {
            session_data->type_expected[source_id] = SEC_BODY_HX;
            prepare_body();
        }
        return;
    }

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
        unsigned token_count = 0;
        int32_t consumed = 0;
        int32_t transfer_encoding;
        do
        {
            transfer_encoding = get_code_from_token_list(te_header.start(), te_header.length(),
                consumed, transfer_encoding_list);
            token_count++;
        }
        while (consumed != -1);

        if (transfer_encoding != TE_CHUNKED)
        {
            add_infraction(INF_BAD_TE_HEADER);
            create_event(EVENT_BAD_TE_HEADER);
        }
        else
        {
            // Last Transfer-Encoding is chunked ...
            if (token_count > 1)
            {
                // ... but there were others before it
                add_infraction(INF_PADDED_TE_HEADER);
                create_event(EVENT_PADDED_TE_HEADER);
            }
            session_data->type_expected[source_id] = SEC_BODY_CHUNK;
            HttpModule::increment_peg_counts(PEG_CHUNKED);
            prepare_body();
            return;
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

// Common activities of preparing for upcoming body
void HttpMsgHeader::prepare_body()
{
    session_data->body_octets[source_id] = 0;
    setup_mime();
    if (!session_data->mime_state[source_id])
    {
        const int64_t& depth = (source_id == SRC_CLIENT) ? params->request_depth :
            params->response_depth;
        session_data->detect_depth_remaining[source_id] = (depth != -1) ? depth : INT64_MAX;
    }
    else
    {
        // File and decode depths are per attachment, so if either is greater than 0 we inspect the
        // full message body. Currently the decode depths are not configurable for http_inspect so
        // are always the default of unlimited, meaning for MIME we always inspect the full message
        // body
        session_data->detect_depth_remaining[source_id] = INT64_MAX;
    }
    if ((source_id == SRC_CLIENT) and params->publish_request_body)
    {
        session_data->publish_octets[source_id] = 0;
        session_data->publish_depth_remaining[source_id] = REQUEST_PUBLISH_DEPTH;
    }
    setup_file_processing();
    setup_encoding_decompression();
    setup_utf_decoding();
    setup_file_decompression();
    update_depth();

    if ((source_id == SRC_SERVER) && (params->script_detection))
        session_data->accelerated_blocking[source_id] = true;

    if (source_id == SRC_CLIENT)
    {
        HttpModule::increment_peg_counts(PEG_REQUEST_BODY);

        // Message bodies for CONNECT requests have no defined semantics
        if ((method_id == METH_CONNECT) && !session_data->for_httpx)
        {
            add_infraction(INF_CONNECT_REQUEST_BODY);
            create_event(EVENT_CONNECT_REQUEST_BODY);
        }
    }
}

void HttpMsgHeader::setup_mime()
{
    // Do we meet all the conditions for MIME file processing?
    if (source_id == SRC_CLIENT)
    {
        const Field& content_type = get_header_value_raw(HEAD_CONTENT_TYPE);
        if (content_type.length() > 0)
        {
            if (boundary_present(content_type))
            {
                mime_boundary_found = true;

                // Generate the unique file id for multi file processing
                set_multi_file_processing_id(get_transaction_id(), session_data->get_hx_stream_id());

                Packet* p = DetectionEngine::get_current_packet();
                const Field& uri = request->get_uri_norm_classic();
                if (uri.length() > 0)
                    session_data->mime_state[source_id] = new MimeSession(p,
                        params->mime_decode_conf, &mime_conf, get_multi_file_processing_id(),
                        uri.start(), uri.length());
                else
                    session_data->mime_state[source_id] = new MimeSession(p,
                        params->mime_decode_conf, &mime_conf, get_multi_file_processing_id());

                // Get host from the header field.
                if (!session_data->mime_state[source_id]->is_host_set())
                {
                    std::string host = get_host_header_field();
                    // Get host from the uri.
                    if (host.empty())
                        host = request->get_host_string();

                    session_data->mime_state[source_id]->set_host_name(host);
                }


                // Show file processing the Content-Type header as if it were regular data.
                // This will enable it to find the boundary string.
                // FIXIT-L develop a proper interface for passing the boundary string.
                // This interface is a leftover from when OHI pushed whole messages through
                // this interface.
                session_data->mime_state[source_id]->process_mime_data(p,
                    content_type.start(), content_type.length(), true,
                    SNORT_FILE_POSITION_UNKNOWN);
                session_data->mime_state[source_id]->process_mime_data(p,
                    (const uint8_t*)"\r\n", 2, true, SNORT_FILE_POSITION_UNKNOWN);
                session_data->file_depth_remaining[source_id] = INT64_MAX;
            }
        }
    }
}

void HttpMsgHeader::setup_file_processing()
{
    if (session_data->mime_state[source_id])
        return;

    // Generate the unique file id for multi file processing and set ID for file_data buffer
    set_multi_file_processing_id(get_transaction_id(), session_data->get_hx_stream_id());

    session_data->file_octets[source_id] = 0;
    const int64_t max_file_depth = FileService::get_max_file_depth();
    if (max_file_depth <= 0)
    {
        session_data->file_depth_remaining[source_id] = 0;
        return;
    }

    session_data->file_depth_remaining[source_id] = max_file_depth;
    FileFlows* file_flows = FileFlows::get_file_flows(flow);
    if (!file_flows)
        session_data->file_depth_remaining[source_id] = 0;
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
            HttpModule::increment_peg_counts(PEG_COMPRESSED_GZIP);
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
            HttpModule::increment_peg_counts(PEG_COMPRESSED_UNKNOWN);
            add_infraction(INF_UNKNOWN_ENCODING);
            create_event(EVENT_UNKNOWN_ENCODING);
            break;
        default:
            // The ones we know by name but don't support
            HttpModule::increment_peg_counts(PEG_COMPRESSED_NOT_SUPPORTED);
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
        assert(false);
        session_data->compression[source_id] = CMP_NONE;
        delete session_data->compress_stream[source_id];
        session_data->compress_stream[source_id] = nullptr;
    }
}

void HttpMsgHeader::setup_utf_decoding()
{
    if (!params->normalize_utf || session_data->mime_state[source_id] )
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

    session_data->utf_state[source_id] = new UtfDecodeSession();
    session_data->utf_state[source_id]->set_decode_utf_state_charset(charset_code);
}

void HttpMsgHeader::setup_file_decompression()
{
    if (session_data->mime_state[source_id] ||
        (!params->decompress_pdf && !params->decompress_swf && !params->decompress_zip))
        return;

    session_data->fd_state[source_id] = File_Decomp_New();
    session_data->fd_state[source_id]->Modes =
        (params->decompress_pdf ? FILE_PDF_DEFL_BIT : 0) |
        (params->decompress_swf ? (FILE_SWF_ZLIB_BIT | FILE_SWF_LZMA_BIT) : 0) |
        (params->decompress_zip ? FILE_ZIP_DEFL_BIT : 0) |
        (params->decompress_vba ? FILE_VBA_EXTR_BIT : 0);
    session_data->fd_state[source_id]->Alert_Callback = HttpMsgBody::fd_event_callback;
    session_data->fd_state[source_id]->Alert_Context = &session_data->fd_alert_context[source_id];
    session_data->fd_state[source_id]->Compr_Depth = 0;
    session_data->fd_state[source_id]->Decompr_Depth = 0;

    (void)File_Decomp_Init(session_data->fd_state[source_id]);
}

// Each file processed has a unique id per flow: hash(source_id, transaction_id, h2_stream_id)
// If this is an HTTP/1 flow, h2_stream_id is 0
void HttpMsgHeader::set_multi_file_processing_id(const uint64_t transaction_id,
    const uint32_t stream_id)
{
    const int data_len = sizeof(source_id) + sizeof(transaction_id) + sizeof(stream_id);
    uint8_t data[data_len];
    memcpy(data, (void*)&source_id, sizeof(source_id));
    uint32_t offset = sizeof(source_id);
    memcpy(data + offset, (void*)&transaction_id, sizeof(transaction_id));
    offset += sizeof(transaction_id);
    memcpy(data + offset, (void*)&stream_id, sizeof(stream_id));

    multi_file_processing_id = str_to_hash(data, data_len);
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
