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
//  @brief      NHttpMsgStart virtual class rolls up all the common elements of request and status line processing.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_start.h"

using namespace NHttpEnums;

void NHttpMsgStart::analyze() {
    start_line.start = msg_text.start;
    start_line.length = find_crlf(start_line.start, msg_text.length, false);
    // special case of TCP close between CR and LF
    if (tcp_close && (msg_text.length == start_line.length) && (start_line.start[start_line.length-1] == '\r')) start_line.length--;
    parse_start_line();
    derive_version_id();
}

void NHttpMsgStart::derive_version_id() {
    if (version.length <= 0) {
        version_id = VERS__NOSOURCE;
        return;
    }
    if (version.length != 8) {
        version_id = VERS__PROBLEMATIC;
        infractions |= INF_BADVERSION;
        return;
    }

    if (memcmp(version.start, "HTTP/", 5) || (version.start[6] != '.')) {
        version_id = VERS__PROBLEMATIC;
        infractions |= INF_BADVERSION;
    }
    else if ((version.start[5] == '1') && (version.start[7] == '1')) {
        version_id = VERS_1_1;
    }
    else if ((version.start[5] == '1') && (version.start[7] == '0')) {
        version_id = VERS_1_0;
    }
    else if ((version.start[5] == '2') && (version.start[7] == '0')) {
        version_id = VERS_2_0;
    }
    else if ((version.start[5] >= '0') && (version.start[5] <= '9') && (version.start[7] >= '0') && (version.start[7] <= '9')) {
        version_id = VERS__OTHER;
        infractions |= INF_UNKNOWNVERSION;
    }
    else {
        version_id = VERS__PROBLEMATIC;
        infractions |= INF_BADVERSION;
    }
}

void NHttpMsgStart::gen_events() {}

ProcessResult NHttpMsgStart::worth_detection() {
    // We combine the start line with the headers for sending to detection if they are already available and we will
    // not exceed paf_max.
    if ((session_data->header_octets_visible[source_id] > 0) &&
        (session_data->type_expected[source_id] == SEC_HEADER) &&
        (msg_text.length + session_data->header_octets_visible[source_id]) <= 63780) {
        return RES_AGGREGATE;
    }
    else {
        return RES_INSPECT;
    }
}

























