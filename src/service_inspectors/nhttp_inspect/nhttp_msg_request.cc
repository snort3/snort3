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

#include "main/snort.h"
#include "detection/detection_util.h"

#include "nhttp_enum.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_header.h"

using namespace NHttpEnums;

NHttpMsgRequest::NHttpMsgRequest(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_,
    SourceId source_id_, bool buf_owner) :
    NHttpMsgStart(buffer, buf_size, session_data_, source_id_, buf_owner)
{
   transaction->set_request(this);
}

void NHttpMsgRequest::parse_start_line() {
    // FIXIT-M this needs to be redesigned to parse a truncated request line and extract the method and URI.
    // The current implementation just gives up if the " HTTP/X.Y" isn't in its proper place at the end of the line.

    // There should be exactly two spaces. One following the method and one before "HTTP/".
    // Additional spaces located within the URI are not allowed by RFC but we will tolerate it
    // <method><SP><URI><SP>HTTP/X.Y
    if (start_line.start[start_line.length-9] != ' ') {
        // space before "HTTP" missing or in wrong place
        infractions += INF_BADREQLINE;
        return;
    }

    int32_t space;
    for (space = 0; space < start_line.length-9; space++) {
        if (start_line.start[space] == ' ') break;
    }
    if (space >= start_line.length-9) {
        // leading space or no space
        infractions += INF_BADREQLINE;
        return;
    }

    method.start = start_line.start;
    method.length = space;
    derive_method_id();
    uri = new NHttpUri(start_line.start + method.length + 1, start_line.length - method.length - 10, method_id);
    version.start = start_line.start + (start_line.length - 8);
    version.length = 8;
    assert (start_line.length == method.length + uri->get_uri().length + version.length + 2);
}

void NHttpMsgRequest::derive_method_id() {
    if (method.length <= 0) {
        method_id = METH__NOSOURCE;
        return;
    }
    method_id = (MethodId) str_to_code(method.start, method.length, method_list);
}

const Field& NHttpMsgRequest::get_uri() {
    if (uri != nullptr) {
        return uri->get_uri();
    }
    return Field::FIELD_NULL;
}

const Field& NHttpMsgRequest::get_uri_norm_legacy() {
    if (uri != nullptr) {
        return uri->get_norm_legacy();
    }
    return Field::FIELD_NULL;
}

void NHttpMsgRequest::gen_events() {
    if (method_id == METH__OTHER) create_event(EVENT_UNKNOWN_METHOD);

    // URI character encoding events
    if (uri && (uri->get_uri_infractions() && INF_URIPERCENTASCII)) create_event(EVENT_ASCII);
    if (uri && (uri->get_uri_infractions() && INF_URIPERCENTUCODE)) create_event(EVENT_U_ENCODE);
    if (uri && (uri->get_uri_infractions() && INF_URI8BITCHAR)) create_event(EVENT_BARE_BYTE);
    if (uri && (uri->get_uri_infractions() && INF_URIPERCENTUTF8)) create_event(EVENT_UTF_8);
    if (uri && (uri->get_uri_infractions() && INF_URIBADCHAR)) create_event(EVENT_NON_RFC_CHAR);

    // URI path events
    if (uri && (uri->get_path_infractions() && INF_URIMULTISLASH)) create_event(EVENT_MULTI_SLASH);
    if (uri && (uri->get_path_infractions() && INF_URIBACKSLASH)) create_event(EVENT_IIS_BACKSLASH);
    if (uri && (uri->get_path_infractions() && INF_URISLASHDOT)) create_event(EVENT_SELF_DIR_TRAV);
    if (uri && (uri->get_path_infractions() && INF_URISLASHDOTDOT)) create_event(EVENT_DIR_TRAV);
    if (uri && (uri->get_path_infractions() && INF_URIROOTTRAV)) create_event(EVENT_WEBROOT_DIR);

}

void NHttpMsgRequest::print_section(FILE *output) {
    NHttpMsgSection::print_message_title(output, "request line");
    fprintf(output, "Version Id: %d\n", version_id);
    fprintf(output, "Method Id: %d\n", method_id);
    if (uri != nullptr) {
        uri->get_uri().print(output, "URI");
        if (uri->get_uri_type() != URI__NOSOURCE) fprintf(output, "URI Type: %d\n", uri->get_uri_type());
        uri->get_scheme().print(output, "Scheme");
        if (uri->get_scheme_id() != SCH__NOSOURCE) fprintf(output, "Scheme Id: %d\n", uri->get_scheme_id());
        uri->get_authority().print(output, "Authority");
        uri->get_host().print(output, "Host Name");
        uri->get_norm_host().print(output, "Normalized Host Name");
        uri->get_port().print(output, "Port");
        if (uri->get_port_value() != STAT_NOSOURCE) fprintf(output, "Port Value: %d\n", uri->get_port_value());
        uri->get_abs_path().print(output, "Absolute Path");
        uri->get_path().print(output, "Path");
        uri->get_norm_path().print(output, "Normalized Path");
        uri->get_query().print(output, "Query");
        uri->get_norm_query().print(output, "Normalized Query");
        uri->get_fragment().print(output, "Fragment");
        uri->get_norm_fragment().print(output, "Normalized Fragment");
        fprintf(output, "URI infractions: overall %" PRIx64 ", format %" PRIx64 ", scheme %" PRIx64 ", host %" PRIx64 ", port %" PRIx64 ", path %"
           PRIx64 ", query %" PRIx64 ", fragment %" PRIx64 "\n",
           uri->get_uri_infractions().get_raw(), uri->get_format_infractions().get_raw(),
           uri->get_scheme_infractions().get_raw(), uri->get_host_infractions().get_raw(),
           uri->get_port_infractions().get_raw(), uri->get_path_infractions().get_raw(),
           uri->get_query_infractions().get_raw(), uri->get_fragment_infractions().get_raw());
    }
    NHttpMsgSection::print_message_wrapup(output);
 }

void NHttpMsgRequest::update_flow() {
    const uint64_t disaster_mask = INF_BADREQLINE;

    // The following logic to determine body type is by no means the last word on this topic.
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->half_reset(source_id);
    }
    else if (infractions && disaster_mask) {
        session_data->type_expected[source_id] = SEC_ABORT;
        session_data->half_reset(source_id);
    }
    else {
        session_data->type_expected[source_id] = SEC_HEADER;
        session_data->version_id[source_id] = version_id;
        session_data->method_id = method_id;
    }
    session_data->section_type[source_id] = SEC__NOTCOMPUTE;
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgRequest::legacy_clients() {
    ClearHttpBuffers();
    legacy_request();
}




