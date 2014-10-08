/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      NHttpMsgSection class is virtual parent for classes that analyze individual HTTP message sections.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_transaction.h"
#include "nhttp_msg_section.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_head_shared.h"

using namespace NHttpEnums;

NHttpMsgSection::NHttpMsgSection(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_,
   SourceId source_id_, bool buf_owner) :
   msg_text(buf_size, buffer),
   session_data(session_data_),
   source_id(source_id_),
   transaction(NHttpTransaction::attach_my_transaction(session_data, source_id)),
   tcp_close(session_data->tcp_close[source_id]),
   scratch_pad(2*buf_size+500),
   infractions(session_data->infractions[source_id]),
   version_id(session_data->version_id[source_id]),
   method_id((source_id == SRC_CLIENT) ? session_data->method_id : METH__NOTPRESENT),
   status_code_num((source_id == SRC_SERVER) ? session_data->status_code_num : STAT_NOTPRESENT),
   delete_msg_on_destruct(buf_owner)
{}

void NHttpMsgSection::print_message_title(FILE *output, const char *title) const {
    fprintf(output, "HTTP message %s:\n", title);
    msg_text.print(output, "Input");
}

void NHttpMsgSection::print_message_wrapup(FILE *output) const {
    fprintf(output, "Infractions: %" PRIx64 ", Events: %" PRIx64 ", TCP Close: %s\n", infractions, events_generated,
       tcp_close ? "True" : "False");
    fprintf(output, "Interface to old clients. http_mask = %x.\n", http_mask);
    for (int i=0; i < HTTP_BUFFER_MAX; i++) {
        if ((1 << i) & http_mask) Field(http_buffer[i].length, http_buffer[i].buf).print(output, http_buffer_name[i]);
    }
    fprintf(output, "\n");
    session_data->show(output);
    fprintf(output, "\n");
}

void NHttpMsgSection::create_event(EventSid sid) {
    const uint32_t NHTTP_GID = 119;
    SnortEventqAdd(NHTTP_GID, (uint32_t)sid);
    events_generated |= (1 << (sid-1));
}

void NHttpMsgSection::legacy_request() {
    NHttpMsgRequest* request = transaction->get_request();
    if (request == nullptr) return;
    if (request->get_method().length > 0) {
        SetHttpBuffer(HTTP_BUFFER_METHOD, request->get_method().start, (unsigned)request->get_method().length);
    }
    if (request->get_uri().length > 0) {
        SetHttpBuffer(HTTP_BUFFER_RAW_URI, request->get_uri().start, (unsigned)request->get_uri().length);
    }
    if (request->get_uri_norm_legacy().length > 0) {
        SetHttpBuffer(HTTP_BUFFER_URI, request->get_uri_norm_legacy().start, (unsigned)request->get_uri_norm_legacy().length);
    }
}

void NHttpMsgSection::legacy_status() {
    NHttpMsgStatus* status = transaction->get_status();
    if (status == nullptr) return;
    if (status->get_status_code().length > 0) {
        SetHttpBuffer(HTTP_BUFFER_STAT_CODE, status->get_status_code().start, (unsigned)status->get_status_code().length);
    }
    if (status->get_reason_phrase().length > 0) {
        SetHttpBuffer(HTTP_BUFFER_STAT_MSG, status->get_reason_phrase().start, (unsigned)status->get_reason_phrase().length);
    }
}

void NHttpMsgSection::legacy_header(bool use_trailer) {
    NHttpMsgHeadShared* header = use_trailer ?
      (NHttpMsgHeadShared*)transaction->get_trailer(source_id) :
      (NHttpMsgHeadShared*)transaction->get_header(source_id);
    if (header == nullptr) return;

    if (header->get_headers().length > 0) {
        SetHttpBuffer(HTTP_BUFFER_RAW_HEADER, header->get_headers().start, (unsigned)header->get_headers().length);
        SetHttpBuffer(HTTP_BUFFER_HEADER, header->get_headers().start, (unsigned)header->get_headers().length);
    }

    legacy_cookie(header, source_id);
 }

void NHttpMsgSection::legacy_cookie(NHttpMsgHeadShared* header, SourceId source_id) {
    HeaderId cookie_head = (source_id == SRC_CLIENT) ? HEAD_COOKIE : HEAD_SET_COOKIE;

    for (int k=0; k < header->get_num_headers(); k++) {
        if (header->get_header_name_id(k) == cookie_head) {
            if (header->get_header_value(k).length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_COOKIE, header->get_header_value(k).start, (unsigned)header->get_header_value(k).length);
            break;
        }
    }

    if (header->get_header_value_norm(cookie_head).length > 0) {
        SetHttpBuffer(HTTP_BUFFER_COOKIE, header->get_header_value_norm(cookie_head).start, (unsigned)header->get_header_value_norm(cookie_head).length);
    }
}







