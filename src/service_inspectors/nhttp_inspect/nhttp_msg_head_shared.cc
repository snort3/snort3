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
//  @brief      NHttpMsgHeadShared virtual class rolls up all the common elements of header processing and trailer processing.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_normalizers.h"
#include "nhttp_msg_head_shared.h"

using namespace NHttpEnums;

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgHeadShared::analyze() {
    parse_whole();
    parse_header_block();
    parse_header_lines();
    for (int j=0; j < num_headers; j++) {
        derive_header_name_id(j);
        if (header_name_id[j] > 0) header_count[header_name_id[j]]++;
    }
}

void NHttpMsgHeadShared::parse_whole() {
    // Normal case with header fields
    if (!tcp_close && (msg_text.length >= 5)) {
        headers.start = msg_text.start;
        headers.length = msg_text.length - 4;
        assert(!memcmp(msg_text.start+msg_text.length-4, "\r\n\r\n", 4));
    }
    // Normal case no header fields
    else if (!tcp_close) {
        headers.length = STAT_NOTPRESENT;
        assert((msg_text.length == 2) && !memcmp(msg_text.start, "\r\n", 2));
    }
    // Normal case with header fields and TCP connection close
    else if ((msg_text.length >= 5) && !memcmp(msg_text.start+msg_text.length-4, "\r\n\r\n", 4)) {
        headers.start = msg_text.start;
        headers.length = msg_text.length - 4;
    }
    // Normal case no header fields and TCP connection close
    else if ((msg_text.length == 2) && !memcmp(msg_text.start, "\r\n", 2)) {
        headers.length = STAT_NOTPRESENT;
    }
    // Abnormal cases truncated by TCP connection close
    else {
        infractions |= INF_TRUNCATED;
        // Lone <CR>
        if ((msg_text.length == 1) && (msg_text.start[0] == '\r')) {
            headers.length = STAT_NOTPRESENT;
        }
        // Truncation occurred somewhere in the header fields
        else {
            headers.start = msg_text.start;
            headers.length = msg_text.length;
            // When present, remove partial <CR><LF><CR><LF> sequence from the end
            if ((msg_text.length >= 4) && !memcmp(msg_text.start+msg_text.length-3, "\r\n\r", 3)) headers.length -= 3;
            else if ((msg_text.length >= 3) && !memcmp(msg_text.start+msg_text.length-2, "\r\n", 2)) headers.length -= 2;
            else if ((msg_text.length >= 2) && (msg_text.start[msg_text.length-1] == '\r')) headers.length -= 1;
        }
    }
}

// Divide up the block of header fields into individual header field lines.
void NHttpMsgHeadShared::parse_header_block() {
    if (headers.length < 0) {
        num_headers = STAT_NOSOURCE;
        return;
    }

    int32_t bytes_used = 0;
    num_headers = 0;
    while (bytes_used < headers.length) {
        header_line[num_headers].start = headers.start + bytes_used;
        header_line[num_headers].length = find_crlf(header_line[num_headers].start, headers.length - bytes_used, true);
        bytes_used += header_line[num_headers++].length + 2;
        if (num_headers >= MAXHEADERS) {
             break;
        }
    }
    if (bytes_used < headers.length) {
        infractions |= INF_TOOMANYHEADERS;
    }
}

// Divide header field lines into field name and field value
void NHttpMsgHeadShared::parse_header_lines() {
    int colon;
    for (int k=0; k < num_headers; k++) {
        for (colon=0; colon < header_line[k].length; colon++) {
            if (header_line[k].start[colon] == ':') break;
        }
        if (colon < header_line[k].length) {
            header_name[k].start = header_line[k].start;
            header_name[k].length = colon;
            header_value[k].start = header_line[k].start + colon + 1;
            header_value[k].length = header_line[k].length - colon - 1;
        }
        else {
            infractions |= INF_BADHEADER;
        }
    }
}

void NHttpMsgHeadShared::derive_header_name_id(int index) {
    // Normalize header field name to lower case for matching purposes
    uint8_t *lower_name;
    if ((lower_name = scratch_pad.request(header_name[index].length)) == nullptr) {
        infractions |= INF_NOSCRATCH;
        header_name_id[index] = HEAD__INSUFMEMORY;
        return;
    }
    norm_to_lower(header_name[index].start, header_name[index].length, lower_name, infractions, nullptr);
    header_name_id[index] = (HeaderId) str_to_code(lower_name, header_name[index].length, header_list);
}

const Field& NHttpMsgHeadShared::get_header_value_norm(NHttpEnums::HeaderId header_id) {
    header_norms[header_id]->normalize(header_id, header_count[header_id], scratch_pad, infractions,
          header_name_id, header_value, num_headers, header_value_norm[header_id]);
    return header_value_norm[header_id];
}

void NHttpMsgHeadShared::gen_events() {
    if (infractions & INF_TOOMANYHEADERS) create_event(EVENT_MAX_HEADERS);
}

ProcessResult NHttpMsgHeadShared::worth_detection() {
    // Do not send empty headers or trailers to detection
    return (headers.length != STAT_NOTPRESENT) ? RES_INSPECT : RES_IGNORE;
}

void NHttpMsgHeadShared::print_headers(FILE *output) {
    char title_buf[100];
    if (num_headers != STAT_NOSOURCE) fprintf(output, "Number of headers: %d\n", num_headers);
    for (int j=0; j < num_headers; j++) {
        snprintf(title_buf, sizeof(title_buf), "Header ID %d", header_name_id[j]);
        header_value[j].print(output, title_buf);
    }
    for (int k=1; k <= HEAD__MAXVALUE-1; k++) {
        if (get_header_value_norm((HeaderId)k).length != STAT_NOSOURCE) {
            snprintf(title_buf, sizeof(title_buf), "Normalized header %d", k);
            get_header_value_norm((HeaderId)k).print(output, title_buf, true);
        }
    }
}





