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
// nhttp_msg_request.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "detection/detection_util.h"

#include "nhttp_enum.h"
#include "nhttp_api.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_header.h"

using namespace NHttpEnums;

NHttpMsgRequest::NHttpMsgRequest(const uint8_t* buffer, const uint16_t buf_size,
    NHttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
    const NHttpParaList* params_) :
    NHttpMsgStart(buffer, buf_size, session_data_, source_id_, buf_owner, flow_, params_)
{
    transaction->set_request(this);
}

void NHttpMsgRequest::parse_start_line()
{
    // Check the version field
    if ((start_line.length < 10) || !is_sp_tab[start_line.start[start_line.length-9]] ||
         memcmp(start_line.start + start_line.length - 8, "HTTP/", 5))
    {
        if (!handle_zero_nine())
        {
            // Just a plain old bad request
            infractions += INF_BAD_REQ_LINE;
            events.generate_misformatted_http(start_line.start, start_line.length);
        }
        return;
    }

    NHttpModule::increment_peg_counts(PEG_REQUEST);

    // The splitter guarantees there will be a non-whitespace at octet 1 and a whitespace within
    // octets 2-81. The following algorithm uses those assumptions.

    int32_t first_space; // first whitespace in request line
    for (first_space = 1; !is_sp_tab[start_line.start[first_space]]; first_space++);

    int32_t first_end; // last whitespace in first clump of whitespace
    for (first_end = first_space+1; is_sp_tab[start_line.start[first_end]]; first_end++);
    first_end--;

    int32_t last_begin; // first whitespace in clump of whitespace before version
    for (last_begin = start_line.length - 10; is_sp_tab[start_line.start[last_begin]];
        last_begin--);
    last_begin++;

    method.start = start_line.start;
    method.length = first_space;
    method_id = (MethodId)str_to_code(method.start, method.length, method_list);

    switch (method_id)
    {
    case METH_GET: NHttpModule::increment_peg_counts(PEG_GET); break;
    case METH_HEAD: NHttpModule::increment_peg_counts(PEG_HEAD); break;
    case METH_POST: NHttpModule::increment_peg_counts(PEG_POST); break;
    case METH_PUT: NHttpModule::increment_peg_counts(PEG_PUT); break;
    case METH_DELETE: NHttpModule::increment_peg_counts(PEG_DELETE); break;
    case METH_CONNECT: NHttpModule::increment_peg_counts(PEG_CONNECT); break;
    case METH_OPTIONS: NHttpModule::increment_peg_counts(PEG_OPTIONS); break;
    case METH_TRACE: NHttpModule::increment_peg_counts(PEG_TRACE); break;
    default: NHttpModule::increment_peg_counts(PEG_OTHER_METHOD); break;
    }

    version.start = start_line.start + (start_line.length - 8);
    version.length = 8;
    derive_version_id();

    if (first_end < last_begin)
    {
        uri = new NHttpUri(start_line.start + first_end + 1, last_begin - first_end - 1,
            method_id, params->uri_param, infractions, events);
    }
    else
    {
        infractions += INF_NO_URI;
        events.create_event(EVENT_URI_MISSING);
    }
}

bool NHttpMsgRequest::handle_zero_nine()
{
    // 0.9 request line is supposed to be "GET <URI>\r\n"
    if ((start_line.length >= 3) &&
        !memcmp(start_line.start, "GET", 3) &&
        ((start_line.length == 3) || is_sp_tab[start_line.start[3]]))
    {
        infractions += INF_ZERO_NINE_REQ;
        events.create_event(EVENT_SIMPLE_REQUEST);
        method.set(3, start_line.start);
        method_id = METH_GET;
        version_id = VERS_0_9;

        // Eliminate the clump of whitespace following GET and possible clump of whitespace at the
        // end and whatever is left is assumed to be the URI
        int32_t uri_begin;
        for (uri_begin = 4; (uri_begin < start_line.length) &&
            is_sp_tab[start_line.start[uri_begin]]; uri_begin++);
        if (uri_begin < start_line.length)
        {
            int32_t uri_end;
            for (uri_end = start_line.length - 1; is_sp_tab[start_line.start[uri_end]]; uri_end--);
            uri = new NHttpUri(start_line.start + uri_begin, uri_end - uri_begin + 1, method_id,
                params->uri_param, infractions, events);
        }
        else
        {
            infractions += INF_NO_URI;
            events.create_event(EVENT_URI_MISSING);
        }
        return true;
    }
    return false;
}

const Field& NHttpMsgRequest::get_uri()
{
    if (uri != nullptr)
    {
        return uri->get_uri();
    }
    return Field::FIELD_NULL;
}

const Field& NHttpMsgRequest::get_uri_norm_classic()
{
    if (uri != nullptr)
    {
        return uri->get_norm_classic();
    }
    return Field::FIELD_NULL;
}

void NHttpMsgRequest::gen_events()
{
    if (infractions & INF_BAD_REQ_LINE)
        return;

    const bool zero_nine = infractions & INF_ZERO_NINE_REQ;

    if ((start_line.start[method.length] == '\t') ||
        (!zero_nine && (start_line.start[start_line.length - 9] == '\t')))
    {
        infractions += INF_REQUEST_TAB;
        events.create_event(EVENT_APACHE_WS);
    }

    // Look for white space issues in and around the URI.
    // Supposed to be <method><space><URI><space><version> or 0.9 format GET<space><URI>
    const int32_t version_start = !zero_nine ? start_line.length - 9 : start_line.length;
    for (int32_t k = method.length + 1; k < version_start; k++)
    {
        if (is_sp_tab[start_line.start[k]])
        {
            if (uri && (uri->get_uri().start <= start_line.start + k) &&
                       (start_line.start + k < uri->get_uri().start + uri->get_uri().length))
            {
                // white space inside the URI is not allowed
                if (start_line.start[k] == ' ')
                {
                    infractions += INF_URI_SPACE;
                    events.create_event(EVENT_UNESCAPED_SPACE_URI);
                }
            }
            else
            {
                // extra white space before or after the URI
                infractions += INF_REQUEST_WS;
                events.create_event(EVENT_IMPROPER_WS);
                if (start_line.start[k] == '\t')
                {
                    // which is also a tab
                    infractions += INF_REQUEST_TAB;
                    events.create_event(EVENT_APACHE_WS);
                }
            }
        }
    }

    if (method_id == METH__OTHER)
        events.create_event(EVENT_UNKNOWN_METHOD);

    if (session_data->zero_nine_expected != 0)
    {
        // Previous 0.9 request on this connection should have been the last request message
        infractions += INF_ZERO_NINE_CONTINUE;
        events.create_event(EVENT_ZERO_NINE_CONTINUE);
    }
    else if (zero_nine && (msg_num != 1))
    {
        // Switched to 0.9 request after previously sending non-0.9 request on this connection
        infractions += INF_ZERO_NINE_NOT_FIRST;
        events.create_event(EVENT_ZERO_NINE_NOT_FIRST);
    }
}

void NHttpMsgRequest::update_flow()
{
    if (infractions & INF_BAD_REQ_LINE)
    {
        session_data->half_reset(source_id);
        session_data->type_expected[source_id] = SEC_ABORT;
    }
    else if (infractions & INF_ZERO_NINE_REQ)
    {
        session_data->half_reset(source_id);
        // There can only be one 0.9 response per connection because it ends the S2C connection. Do
        // not allow a pipelined request to overwrite a previous 0.9 setup.
        if (session_data->zero_nine_expected == 0)
        {
            // FIXIT-L Add a configuration option to not do this. This would support an HTTP server
            // that responds to a 0.9 GET request with a full-blown 1.0 or 1.1 response with status
            // line and headers.
            session_data->zero_nine_expected = msg_num;
        }
    }
    else
    {
        session_data->type_expected[source_id] = SEC_HEADER;
        session_data->version_id[source_id] = version_id;
        session_data->method_id = method_id;
        session_data->infractions[source_id].reset();
        session_data->events[source_id].reset();
    }
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;
}

#ifdef REG_TEST

void NHttpMsgRequest::print_section(FILE* output)
{
    NHttpMsgSection::print_section_title(output, "request line");
    fprintf(output, "Version Id: %d\n", version_id);
    fprintf(output, "Method Id: %d\n", method_id);
    if (uri != nullptr)
    {
        uri->get_uri().print(output, "URI");
        fprintf(output, "URI Type: %d\n", uri->get_uri_type());
        uri->get_scheme().print(output, "Scheme");
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
    get_classic_buffer(NHTTP_BUFFER_METHOD, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_METHOD-1]);
    get_classic_buffer(NHTTP_BUFFER_RAW_URI, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_RAW_URI-1]);
    get_classic_buffer(NHTTP_BUFFER_URI, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_URI-1]);
    get_classic_buffer(NHTTP_BUFFER_VERSION, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_VERSION-1]);
    get_classic_buffer(NHTTP_BUFFER_RAW_REQUEST, 0, 0).print(output,
        NHttpApi::classic_buffer_names[NHTTP_BUFFER_RAW_REQUEST-1]);
    NHttpMsgSection::print_section_wrapup(output);
}

#endif

