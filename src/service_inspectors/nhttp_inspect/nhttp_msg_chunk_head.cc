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
//  @brief      NHttpMsgChunkHead class analyzes header line for a chunk.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_chunk_head.h"

using namespace NHttpEnums;

NHttpMsgChunkHead::NHttpMsgChunkHead(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_, SourceId source_id_) :
   NHttpMsgSection(buffer, buf_size, session_data_, source_id_), body_sections(session_data->body_sections[source_id]),
   num_chunks(session_data->num_chunks[source_id])
{
   transaction->set_other(this);
}


// Convert the hexadecimal chunk length.
// RFC says that zero may be written with multiple digits "000000".
// Arbitrary limit of 15 hex digits not including leading zeros ensures in a simple way against 64-bit overflow and should be
// vastly bigger than any legitimate chunk.
void NHttpMsgChunkHead::derive_chunk_length() {
    if (chunk_size.length <= 0) {
        data_length = STAT_NOSOURCE;
        infractions |= INF_BADCHUNKSIZE;
        return;
    }
    data_length = 0;
    int non_leading_zeros = 0;
    for (int k=0; k < chunk_size.length; k++) {
        if (non_leading_zeros || (chunk_size.start[k] != '0')) non_leading_zeros++;
        if (non_leading_zeros > 15) {
            data_length = STAT_PROBLEMATIC;
            infractions |= INF_BADCHUNKSIZE;
            return;
        }

        data_length *= 16;
        if ((chunk_size.start[k] >= '0') && (chunk_size.start[k] <= '9')) data_length += chunk_size.start[k] - '0';
        else if ((chunk_size.start[k] >= 'A') && (chunk_size.start[k] <= 'F')) data_length += chunk_size.start[k] - 'A' + 10;
        else if ((chunk_size.start[k] >= 'a') && (chunk_size.start[k] <= 'f')) data_length += chunk_size.start[k] - 'a' + 10;
        else {
            data_length = STAT_PROBLEMATIC;
            infractions |= INF_BADCHUNKSIZE;
            return;
        }
    }
}

void NHttpMsgChunkHead::analyze() {
    body_sections++;
    // First section in a new chunk is just the start line.
    num_chunks++;
    start_line.start = msg_text.start;
    if (!tcp_close) {
        start_line.length = msg_text.length - 2;
    }
    else {
        start_line.length = find_crlf(start_line.start, msg_text.length, false);
    }
    chunk_size.start = msg_text.start;
    // Start line format is chunk size in hex followed by optional semicolon and extensions field
    for (chunk_size.length = 0; (chunk_size.length < start_line.length) && (start_line.start[chunk_size.length] != ';'); chunk_size.length++);
    if (chunk_size.length == start_line.length) {
        chunk_extensions.length = STAT_NOTPRESENT;
    }
    else if (chunk_size.length == start_line.length - 1) {
        chunk_extensions.length = STAT_EMPTYSTRING;
    }
    else {
        chunk_extensions.start = msg_text.start + chunk_size.length + 1;
        chunk_extensions.length = start_line.length - chunk_size.length - 1;
    }
    derive_chunk_length();
    if (tcp_close) infractions |= INF_TRUNCATED;
}

void NHttpMsgChunkHead::gen_events() {}

void NHttpMsgChunkHead::print_section(FILE *output) {
    NHttpMsgSection::print_message_title(output, "chunk header");
    fprintf(output, "Chunk size: %" PRIi64 "\n", data_length);
    chunk_extensions.print(output, "Chunk extensions");
    NHttpMsgSection::print_message_wrapup(output);
}

void NHttpMsgChunkHead::update_flow() {
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->half_reset(source_id);
    }
    else if (data_length > 0) {
        session_data->type_expected[source_id] = SEC_CHUNKBODY;
        session_data->octets_expected[source_id] = data_length+2;
        session_data->body_sections[source_id] = body_sections;
        session_data->num_chunks[source_id] = num_chunks;
        session_data->data_length[source_id] = data_length;
        session_data->chunk_sections[source_id] = 0;
        session_data->chunk_octets[source_id] = 0;
    }
    else {
        // This was zero-length last chunk, trailer comes next
        session_data->type_expected[source_id] = SEC_TRAILER;
    }
}


// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgChunkHead::legacy_clients() {
    ClearHttpBuffers();
    legacy_request();
    legacy_status();
    legacy_header(false);
    if (start_line.length > 0) SetHttpBuffer(HTTP_BUFFER_CLIENT_BODY, start_line.start, (unsigned)start_line.length);
}










