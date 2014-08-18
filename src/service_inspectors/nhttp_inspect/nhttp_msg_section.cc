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
#include "nhttp_msg_section.h"

using namespace NHttpEnums;

NHttpMsgSection::NHttpMsgSection(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_, SourceId source_id_) :
   session_data(session_data_), source_id(source_id_), tcp_close(session_data->tcp_close[source_id]), scratch_pad(2*buf_size+500),
   infractions(session_data->infractions[source_id]), version_id(session_data->version_id[source_id]),
   method_id(session_data->method_id[source_id]), status_code_num(session_data->status_code_num[source_id])
{
    msg_text.start = buffer;
    msg_text.length = buf_size;
}

// Return the number of octets before the first CRLF. Return length if CRLF not present.
//
// wrappable: CRLF does not count in a header field when immediately followed by <SP> or <LF>. These whitespace characters
// at the beginning of the next line indicate that the previous header has wrapped and is continuing on the next line.
uint32_t NHttpMsgSection::find_crlf(const uint8_t* buffer, int32_t length, bool wrappable) {
    for (int32_t k=0; k < length-1; k++) {
        if ((buffer[k] == '\r') && (buffer[k+1] == '\n'))
            if (!wrappable || (k+2 >= length) || ((buffer[k+2] != ' ') && (buffer[k+2] != '\t'))) return k;
    }
    return length;
}

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
}

void NHttpMsgSection::create_event(EventSid sid) {
    const uint32_t NHTTP_GID = 119;
    SnortEventqAdd(NHTTP_GID, (uint32_t)sid);
    events_generated |= (1 << (sid-1));
}

















