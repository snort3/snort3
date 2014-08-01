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
    startLine.start = msgText.start;
    startLine.length = findCrlf(startLine.start, msgText.length, false);
    // special case of TCP close between CR and LF
    if (tcpClose && (msgText.length == startLine.length) && (startLine.start[startLine.length-1] == '\r')) startLine.length--;
    parseStartLine();
    deriveVersionId();
}

void NHttpMsgStart::deriveVersionId() {
    if (version.length <= 0) {
        versionId = VERS__NOSOURCE;
        return;
    }
    if (version.length != 8) {
        versionId = VERS__PROBLEMATIC;
        infractions |= INF_BADVERSION;
        return;
    }

    if (memcmp(version.start, "HTTP/", 5) || (version.start[6] != '.')) {
        versionId = VERS__PROBLEMATIC;
        infractions |= INF_BADVERSION;
    }
    else if ((version.start[5] == '1') && (version.start[7] == '1')) {
        versionId = VERS_1_1;
    }
    else if ((version.start[5] == '1') && (version.start[7] == '0')) {
        versionId = VERS_1_0;
    }
    else if ((version.start[5] == '2') && (version.start[7] == '0')) {
        versionId = VERS_2_0;
    }
    else if ((version.start[5] >= '0') && (version.start[5] <= '9') && (version.start[7] >= '0') && (version.start[7] <= '9')) {
        versionId = VERS__OTHER;
        infractions |= INF_UNKNOWNVERSION;
    }
    else {
        versionId = VERS__PROBLEMATIC;
        infractions |= INF_BADVERSION;
    }
}

void NHttpMsgStart::genEvents() {}

