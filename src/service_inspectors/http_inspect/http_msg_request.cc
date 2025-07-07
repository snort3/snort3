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
// http_msg_request.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_request.h"

#include "main/snort_config.h"
#include "pub_sub/intrinsic_event_ids.h"

#include "http_api.h"
#include "http_common.h"
#include "http_enum.h"
#include "http_test_manager.h"

using namespace HttpCommon;
using namespace HttpEnums;
using namespace snort;
using namespace std;

HttpMsgRequest::HttpMsgRequest(const uint8_t* buffer, const uint16_t buf_size,
    HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const HttpParaList* params_) :
    HttpMsgStart(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{
    transaction->set_request(this);
    get_related_sections();
}

HttpMsgRequest::~HttpMsgRequest()
{
    delete uri;
    delete query_params;
    delete body_params;
}

void HttpMsgRequest::parse_start_line()
{
    // Version field
    if ((start_line.length() < 10) || !is_sp_tab[start_line.start()[start_line.length()-9]] ||
        memcmp(start_line.start() + start_line.length() - 8, "HTTP/", 5))
    {
        // Something is wrong with this message. Check for lower case letters in HTTP-name.
        if ((start_line.length() >= 10) && is_sp_tab[start_line.start()[start_line.length()-9]] &&
            http_name_nocase_ok(start_line.start() + start_line.length() - 8))
        {
            add_infraction(INF_VERSION_NOT_UPPERCASE);
            create_event(EVENT_VERSION_NOT_UPPERCASE);
        }
        // Check for version 0.9 request.
        else if (handle_zero_nine())
        {
            return;
        }
        // Just a plain old bad request
        else
        {
            add_infraction(INF_BAD_REQ_LINE);
            session_data->events[source_id]->create_event(HttpEnums::EVENT_BAD_REQ_LINE);
            session_data->events[source_id]->create_event(HttpEnums::EVENT_LOSS_OF_SYNC);
            return;
        }
    }

    version.set(8, start_line.start() + (start_line.length() - 8));
    derive_version_id();

    HttpModule::increment_peg_counts(PEG_REQUEST);

    // The splitter guarantees there will be a non-whitespace at octet 1 and a whitespace within
    // octets 2-81. The following algorithm uses those assumptions.

    int32_t first_space; // first whitespace in request line
    for (first_space = 1; !is_sp_tab[start_line.start()[first_space]]; first_space++);

    int32_t first_end; // last whitespace in first clump of whitespace
    for (first_end = first_space+1; is_sp_tab[start_line.start()[first_end]]; first_end++);
    first_end--;

    int32_t last_begin; // first whitespace in clump of whitespace before version
    for (last_begin = start_line.length() - 10; is_sp_tab[start_line.start()[last_begin]];
        last_begin--);
    last_begin++;

    method.set(first_space, start_line.start());
    method_id = (MethodId)str_to_code(method.start(), method.length(), method_list);

    switch (method_id)
    {
    case METH_GET: HttpModule::increment_peg_counts(PEG_GET); break;
    case METH_HEAD: HttpModule::increment_peg_counts(PEG_HEAD); break;
    case METH_POST: HttpModule::increment_peg_counts(PEG_POST); break;
    case METH_PUT: HttpModule::increment_peg_counts(PEG_PUT); break;
    case METH_DELETE: HttpModule::increment_peg_counts(PEG_DELETE); break;
    case METH_CONNECT: HttpModule::increment_peg_counts(PEG_CONNECT); break;
    case METH_OPTIONS: HttpModule::increment_peg_counts(PEG_OPTIONS); break;
    case METH_TRACE: HttpModule::increment_peg_counts(PEG_TRACE); break;
    default: HttpModule::increment_peg_counts(PEG_OTHER_METHOD); break;
    }

    if (first_end < last_begin)
    {
        uri = new HttpUri(start_line.start() + first_end + 1, last_begin - first_end - 1,
            method_id, params->uri_param, transaction->get_infractions(source_id),
            session_data->events[source_id]);
    }
    else
    {
        add_infraction(INF_NO_URI);
        create_event(EVENT_URI_MISSING);
    }
}

bool HttpMsgRequest::http_name_nocase_ok(const uint8_t* start)
{
    return ((start[0] == 'H') || (start[0] == 'h')) &&
           ((start[1] == 'T') || (start[1] == 't')) &&
           ((start[2] == 'T') || (start[2] == 't')) &&
           ((start[3] == 'P') || (start[3] == 'p')) &&
           (start[4] == '/');
}

bool HttpMsgRequest::handle_zero_nine()
{
    // FIXIT-M The following test seems too permissive about what constitutes HTTP/0.9. Consider
    // not accepting "URIs" with internal whitespace or nonprinting characters.
    // 0.9 request line is supposed to be "GET <URI>\r\n"
    if ((start_line.length() >= 3) &&
        !memcmp(start_line.start(), "GET", 3) &&
        ((start_line.length() == 3) || is_sp_tab[start_line.start()[3]]))
    {
        add_infraction(INF_ZERO_NINE_REQ);
        create_event(EVENT_SIMPLE_REQUEST);
        method.set(3, start_line.start());
        method_id = METH_GET;
        version_id = VERS_0_9;

        // Eliminate the clump of whitespace following GET and possible clump of whitespace at the
        // end and whatever is left is assumed to be the URI
        int32_t uri_begin;
        for (uri_begin = 4; (uri_begin < start_line.length()) &&
            is_sp_tab[start_line.start()[uri_begin]]; uri_begin++);
        if (uri_begin < start_line.length())
        {
            int32_t uri_end;
            for (uri_end = start_line.length() - 1; is_sp_tab[start_line.start()[uri_end]];
                uri_end--);
            uri = new HttpUri(start_line.start() + uri_begin, uri_end - uri_begin + 1, method_id,
                params->uri_param, transaction->get_infractions(source_id),
                session_data->events[source_id]);
        }
        else
        {
            add_infraction(INF_NO_URI);
            create_event(EVENT_URI_MISSING);
        }
        return true;
    }
    return false;
}

const Field& HttpMsgRequest::get_uri()
{
    if (uri != nullptr)
    {
        return uri->get_uri();
    }
    return Field::FIELD_NULL;
}

const Field& HttpMsgRequest::get_uri_norm_classic()
{
    if (uri != nullptr)
    {
        return uri->get_norm_classic();
    }
    return Field::FIELD_NULL;
}

ParameterMap& HttpMsgRequest::get_query_params()
{
    if (query_params == nullptr)
        query_params = new ParameterMap;

    return *query_params;
}

ParameterMap& HttpMsgRequest::get_body_params()
{
    if (body_params == nullptr)
        body_params = new ParameterMap;

    return *body_params;
}

void HttpMsgRequest::clear_body_params()
{
    if (body_params != nullptr)
        body_params->clear();
}

void HttpMsgRequest::gen_events()
{
    if (*transaction->get_infractions(source_id) & INF_BAD_REQ_LINE)
        return;

    const bool zero_nine = *transaction->get_infractions(source_id) & INF_ZERO_NINE_REQ;

    if ((start_line.start()[method.length()] == '\t') ||
        (!zero_nine && (start_line.start()[start_line.length() - 9] == '\t')))
    {
        add_infraction(INF_REQUEST_TAB);
        create_event(EVENT_APACHE_WS);
    }

    // Look for white space issues in and around the URI.
    // Supposed to be <method><space><URI><space><version> or 0.9 format GET<space><URI>
    const int32_t version_start = !zero_nine ? start_line.length() - 9 : start_line.length();
    for (int32_t k = method.length() + 1; k < version_start; k++)
    {
        if (is_sp_tab[start_line.start()[k]])
        {
            if (uri && (uri->get_uri().start() <= start_line.start() + k) &&
                       (start_line.start() + k < uri->get_uri().start() + uri->get_uri().length()))
            {
                // white space inside the URI is not allowed
                if (start_line.start()[k] == ' ')
                {
                    add_infraction(INF_URI_SPACE);
                    create_event(EVENT_UNESCAPED_SPACE_URI);
                }
            }
            else
            {
                // extra white space before or after the URI
                add_infraction(INF_REQUEST_WS);
                create_event(EVENT_IMPROPER_WS);
                if (start_line.start()[k] == '\t')
                {
                    // which is also a tab
                    add_infraction(INF_REQUEST_TAB);
                    create_event(EVENT_APACHE_WS);
                }
            }
        }
    }

    bool known_method = false;
    assert(method.length() > 0);
    if (!params->allowed_methods.empty() or !params->disallowed_methods.empty())
    {
        string method_str((const char*)method.start(), method.length());

        if (!params->allowed_methods.empty())
        {
            const set<string>::iterator it = params->allowed_methods.find(method_str);
            if (it == params->allowed_methods.end())
            {
                add_infraction(INF_METHOD_NOT_ON_ALLOWED_LIST);
                create_event(EVENT_DISALLOWED_METHOD);
            }
            else
                known_method = true;
        }
        else
        {
            const set<string>::iterator it = params->disallowed_methods.find(method_str);
            if (it != params->disallowed_methods.end())
            {
                add_infraction(INF_METHOD_ON_DISALLOWED_LIST);
                create_event(EVENT_DISALLOWED_METHOD);
                known_method = true;
            }
        }
    }

    if (method_id == METH__OTHER && !known_method)
        create_event(EVENT_UNKNOWN_METHOD);

    if (uri && uri->get_scheme().length() > LONG_SCHEME_LENGTH)
    {
        create_event(EVENT_LONG_SCHEME);
        add_infraction(INF_LONG_SCHEME);
    }

    if (session_data->zero_nine_expected != 0)
    {
        // Previous 0.9 request on this connection should have been the last request message
        add_infraction(INF_ZERO_NINE_CONTINUE);
        create_event(EVENT_ZERO_NINE_CONTINUE);
    }
    else if (zero_nine && (trans_num != 1))
    {
        // Switched to 0.9 request after previously sending non-0.9 request on this connection
        add_infraction(INF_ZERO_NINE_NOT_FIRST);
        create_event(EVENT_ZERO_NINE_NOT_FIRST);
    }
}

void HttpMsgRequest::update_flow()
{
    if (*transaction->get_infractions(source_id) & INF_BAD_REQ_LINE)
    {
        session_data->half_reset(source_id);
        session_data->type_expected[source_id] = SEC_ABORT;
        return;
    }

    if (*transaction->get_infractions(source_id) & INF_ZERO_NINE_REQ)
    {
        session_data->half_reset(source_id);
        // There can only be one 0.9 response per connection because it ends the S2C connection. Do
        // not allow a pipelined request to overwrite a previous 0.9 setup.
        if (session_data->zero_nine_expected == 0)
        {
            // FIXIT-L Add a configuration option to not do this. This would support an HTTP server
            // that responds to a 0.9 GET request with a full-blown 1.0 or 1.1 response with status
            // line and headers.
            session_data->zero_nine_expected = trans_num;
        }
        return;
    }

    if (method_id == METH_CONNECT)
    {
        session_data->last_request_was_connect = true;
    }

    session_data->type_expected[source_id] = SEC_HEADER;
    session_data->version_id[source_id] = version_id;
    session_data->method_id = method_id;
}

void HttpMsgRequest::publish(unsigned)
{
    if (!session_data->ssl_search_abandoned && trans_num > 1 &&
        !flow->flags.data_decrypted && get_method_id() != METH_CONNECT)
    {
        session_data->ssl_search_abandoned = true;
        DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::SSL_SEARCH_ABANDONED, DetectionEngine::get_current_packet());
    }

    if (SnortConfig::get_conf()->aux_ip_is_enabled())
    {
        string aux_ip_str = get_aux_ip();

        if (!aux_ip_str.empty())
        {
            SfIp aux_ip;
            if (parse_ip_from_uri(aux_ip_str, aux_ip))
                flow->set_attr(aux_ip);
        }
    }
}

string HttpMsgRequest::get_aux_ip()
{
    string ip_str;

    if (!uri)
        return ip_str;

    const Field& auth = uri->get_authority();

    if (!(auth.length() > 0) or auth.start() == nullptr)
        return ip_str;

    // The following rules out most host values that are not IP addresses before we
    // waste resources on them. The subscriber must do more careful validation. IPv4
    // must begin with a digit while IPv6 within a URI must begin with a '['.
    if (((auth.start()[0] >= '0') && (auth.start()[0] <= '9')) ||
        (auth.start()[0] == '['))
    {
        const Field& host = uri->get_host();
        if (host.length() > 0)
        {
            ip_str = string((const char*)host.start(), (size_t)host.length());
            return ip_str;
        }
    }

    return ip_str;
}

std::string HttpMsgRequest::get_host_string()
{
    if (!uri)
        return "";

    const Field& host = uri->get_host();
    if (host.length() > STAT_EMPTY_STRING)
        return string((const char*)host.start(), (size_t)host.length());
    return "";
}

#ifdef REG_TEST

void HttpMsgRequest::print_section(FILE* output)
{
    HttpMsgSection::print_section_title(output, "request line");
    fprintf(output, "Version ID: %d\n", version_id);
    fprintf(output, "Method ID: %d\n", method_id);
    if (uri != nullptr)
    {
        uri->get_uri().print(output, "URI");
        fprintf(output, "URI Type: %d\n", uri->get_uri_type());
        uri->get_scheme().print(output, "Scheme");
        uri->get_norm_scheme().print(output, "Normalized Scheme");
        uri->get_authority().print(output, "Authority");
        uri->get_host().print(output, "Host Name");
        uri->get_norm_host().print(output, "Normalized Host Name");
        uri->get_port().print(output, "Port");
        uri->get_abs_path().print(output, "Absolute Path");
        uri->get_path().print(output, "Path");
        uri->get_norm_path().print(output, "Normalized Path");
        uri->get_query().print(output, "Query");
        uri->get_norm_query().print(output, "Normalized Query");
        uri->get_fragment().print(output, "Fragment");
        uri->get_norm_fragment().print(output, "Normalized Fragment");
    }
    get_classic_buffer(HTTP_BUFFER_METHOD, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_METHOD-1]);
    get_classic_buffer(HTTP_BUFFER_RAW_URI, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_URI-1]);
    get_classic_buffer(HTTP_BUFFER_URI, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_URI-1]);
    get_classic_buffer(HTTP_BUFFER_VERSION, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_VERSION-1]);
    get_classic_buffer(HTTP_BUFFER_RAW_REQUEST, 0, 0).print(output,
        HttpApi::classic_buffer_names[HTTP_BUFFER_RAW_REQUEST-1]);
    HttpMsgSection::print_section_wrapup(output);
}

#endif

