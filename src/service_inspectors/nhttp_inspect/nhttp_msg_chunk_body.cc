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
//  @brief      NHttpMsgChunkBody class analyzes data portion (not start line) of an HTTP chunk.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_chunk_body.h"

using namespace NHttpEnums;

NHttpMsgChunkBody::NHttpMsgChunkBody(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_, SourceId source_id_) :
   NHttpMsgBody(buffer, buf_size, session_data_, source_id_), /* num_chunks(session_data->num_chunks[source_id]), &&& */
   chunk_sections(session_data->chunk_sections[source_id]), chunk_octets(session_data->chunk_octets[source_id]) {}

void NHttpMsgChunkBody::analyze() {
    body_sections++;
    chunk_octets += msg_text.length;
    body_octets += msg_text.length;
    int term_crlf_bytes = 0;
    if (chunk_octets > data_length) {
        // Final <CR><LF> are not data and do not belong in octet total or data field
        term_crlf_bytes = chunk_octets - data_length;
        assert(term_crlf_bytes <= 2);
        body_octets -= term_crlf_bytes;
        // Check for correct CRLF termination. Beware the section might break just before chunk end.
        if ( ! ( ((term_crlf_bytes == 2) && (msg_text.length >= 2) && (msg_text.start[msg_text.length-2] == '\r') && (msg_text.start[msg_text.length-1] == '\n')) ||
                 ((term_crlf_bytes == 2) && (msg_text.length == 1) && (msg_text.start[msg_text.length-1] == '\n')) ||
                 ((term_crlf_bytes == 1) && (msg_text.start[msg_text.length-1] == '\r')) ) ) {
            infractions |= INF_BROKENCHUNK;
        }
    }

    data.start = msg_text.start;
    data.length = msg_text.length - term_crlf_bytes;

    chunk_sections++;
    // The following statement tests for the case where streams underfulfilled flush due to a TCP connection close
    if ((msg_text.length < 16384) && (body_octets + term_crlf_bytes < data_length + 2)) tcp_close = true;
    if (tcp_close) infractions |= INF_TRUNCATED;
}


void NHttpMsgChunkBody::gen_events() {}

void NHttpMsgChunkBody::print_section(FILE *output) {
    NHttpMsgSection::print_message_title(output, "chunk body");
    fprintf(output, "Expected chunk length %" PRIi64 ", cumulative sections %" PRIi64 ", cumulative octets %" PRIi64 "\n", data_length, body_sections, body_octets);
    fprintf(output, "cumulative chunk sections %" PRIi64 ", cumulative chunk octets %" PRIi64 "\n", chunk_sections, chunk_octets);
    data.print(output, "Data");
    NHttpMsgSection::print_message_wrapup(output);
}

void NHttpMsgChunkBody::update_flow() {
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->half_reset(source_id);
    }
    else if (chunk_octets < data_length + 2) {
        session_data->body_sections[source_id] = body_sections;
        session_data->body_octets[source_id] = body_octets;
        session_data->chunk_sections[source_id] = chunk_sections;
        session_data->chunk_octets[source_id] = chunk_octets;
    }
    else {
        session_data->type_expected[source_id] = SEC_CHUNKHEAD;
        session_data->octets_expected[source_id] = STAT_NOTPRESENT;
        session_data->data_length[source_id] = STAT_NOTPRESENT;
        session_data->body_sections[source_id] = body_sections;
        session_data->body_octets[source_id] = body_octets;
        session_data->chunk_sections[source_id] = STAT_NOTPRESENT;
        session_data->chunk_octets[source_id] = STAT_NOTPRESENT;
    }
}


































