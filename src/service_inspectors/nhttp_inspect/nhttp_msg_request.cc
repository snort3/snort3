//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
        infractions += INF_BAD_REQ_LINE;
        events.create_event(EVENT_LOSS_OF_SYNC);
        return;
    }

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

    version.start = start_line.start + (start_line.length - 8);
    version.length = 8;
    derive_version_id();

    if (first_end < last_begin)
    {
        uri = new NHttpUri(start_line.start + first_end + 1, last_begin - first_end - 1,
            method_id, infractions, events);
    }
    else
    {
        infractions += INF_NO_URI;
        events.create_event(EVENT_URI_MISSING);
    }
}

const Field& NHttpMsgRequest::get_uri()
{
    if (uri != nullptr)
    {
        return uri->get_uri();
    }
    return Field::FIELD_NULL;
}

const Field& NHttpMsgRequest::get_uri_norm_legacy()
{
    if (uri != nullptr)
    {
        return uri->get_norm_legacy();
    }
    return Field::FIELD_NULL;
}

void NHttpMsgRequest::gen_events()
{
    if (infractions & INF_BAD_REQ_LINE)
        return;

    if ((start_line.start[method.length] == '\t') ||
        (start_line.start[start_line.length - 9] == '\t'))
    {
        infractions += INF_REQUEST_TAB;
        events.create_event(EVENT_APACHE_WS);
    }

    for (int k = method.length + 1; k < start_line.length - 9; k++)
    {
        if (is_sp_tab[start_line.start[k]])
        {
            if (uri && (uri->get_uri().start <= start_line.start + k) &&
                       (start_line.start + k < uri->get_uri().start + uri->get_uri().length))
            {
                // inside the URI
                if (start_line.start[k] == ' ')
                {
                    infractions += INF_URI_SPACE;
                    events.create_event(EVENT_UNESCAPED_SPACE_URI);
                }
            }
            else
            {
                infractions += INF_REQUEST_WS;
                events.create_event(EVENT_IMPROPER_WS);
                if (start_line.start[k] == '\t')
                {
                    infractions += INF_REQUEST_TAB;
                    events.create_event(EVENT_APACHE_WS);
                }
            }
        }
    }

    if (method_id == METH__OTHER)
        events.create_event(EVENT_UNKNOWN_METHOD);
}

void NHttpMsgRequest::print_section(FILE* output)
{
    NHttpMsgSection::print_message_title(output, "request line");
    fprintf(output, "Version Id: %d\n", version_id);
    fprintf(output, "Method Id: %d\n", method_id);
    if (uri != nullptr)
    {
        uri->get_uri().print(output, "URI");
        fprintf(output, "URI Type: %d\n", uri->get_uri_type());
        uri->get_scheme().print(output, "Scheme");
        if (uri->get_scheme_id() != SCH__NOSOURCE)
            fprintf(output, "Scheme Id: %d\n", uri->get_scheme_id());
        uri->get_authority().print(output, "Authority");
        uri->get_host().print(output, "Host Name");
        uri->get_norm_host().print(output, "Normalized Host Name");
        uri->get_port().print(output, "Port");
        if (uri->get_port_value() != STAT_NOSOURCE)
            fprintf(output, "Port Value: %d\n", uri->get_port_value());
        uri->get_abs_path().print(output, "Absolute Path");
        uri->get_path().print(output, "Path");
        uri->get_norm_path().print(output, "Normalized Path");
        uri->get_query().print(output, "Query");
        uri->get_norm_query().print(output, "Normalized Query");
        uri->get_fragment().print(output, "Fragment");
        uri->get_norm_fragment().print(output, "Normalized Fragment");
    }
    NHttpMsgSection::print_message_wrapup(output);
}

void NHttpMsgRequest::update_flow()
{
    // The following logic to determine body type is by no means the last word on this topic.
    if (infractions & INF_BAD_REQ_LINE)
    {
        session_data->type_expected[source_id] = SEC_ABORT;
        session_data->half_reset(source_id);
    }
    else
    {
        session_data->type_expected[source_id] = SEC_HEADER;
        session_data->version_id[source_id] = version_id;
        session_data->method_id = method_id;
        session_data->infractions[source_id].reset();
        session_data->events[source_id].reset();
    }
    session_data->section_type[source_id] = SEC__NOTCOMPUTE;
}

