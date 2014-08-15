/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
//  @brief      NHttpMsgBody class analyzes individual HTTP message bodies. Message chunks are handled in NHttpMsgChunk.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_body.h"

using namespace NHttpEnums;

NHttpMsgBody::NHttpMsgBody(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_, SourceId source_id_) :
   NHttpMsgSection(buffer, buf_size, session_data_, source_id_), data_length(session_data->data_length[source_id]),
   body_sections(session_data->body_sections[source_id]), body_octets(session_data->body_octets[source_id]) {
    delete session_data->latest_other[source_id];
    session_data->latest_other[source_id] = this;
}

void NHttpMsgBody::analyze() {
    body_sections++;
    body_octets += msg_text.length;
    data.start = msg_text.start;
    data.length = msg_text.length;

    // The following statement tests for the case where streams underfulfilled flush due to a TCP connection close
    if ((msg_text.length < 16384) && (body_octets < data_length)) tcp_close = true;
    if (tcp_close && (body_octets < data_length)) infractions |= INF_TRUNCATED;
}

void NHttpMsgBody::gen_events() {
}

void NHttpMsgBody::print_section(FILE *output) {
    NHttpMsgSection::print_message_title(output, "body");
    fprintf(output, "Expected data length %" PRIi64 ", sections seen %" PRIi64 ", octets seen %" PRIi64 "\n", data_length, body_sections, body_octets);
    data.print(output, "Data");
    NHttpMsgSection::print_message_wrapup(output);
}

void NHttpMsgBody::update_flow() {
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->half_reset(source_id);
    }
    else if (body_octets < data_length) {
        // More body coming
        session_data->body_sections[source_id] = body_sections;
        session_data->body_octets[source_id] = body_octets;
    }
    else {
        // End of message
        session_data->type_expected[source_id] = (source_id == SRC_CLIENT) ? SEC_REQUEST : SEC_STATUS;
        session_data->half_reset(source_id);
    }
}


// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgBody::legacy_clients() {
    ClearHttpBuffers();
    if (data.length > 0) SetHttpBuffer(HTTP_BUFFER_CLIENT_BODY, data.start, (unsigned)data.length);
}
































