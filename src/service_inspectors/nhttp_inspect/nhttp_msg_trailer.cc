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
//  @brief      NHttpMsgTrailer class analyzes HTTP chunked message trailers.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_trailer.h"

using namespace NHttpEnums;

void NHttpMsgTrailer::parseWhole() {
    // The following if-else ladder puts the extremely common normal cases at the beginning and the rare pathological cases at the end
    // Normal case with no trailer fields
    if (!tcpClose && (length == 2)) {
        headers.length = STAT_NOTPRESENT;
    }
    // Normal case with trailer fields
    else if (!tcpClose) {
        headers.start = msgText;
        headers.length = length - 4;
    }
    // Normal case no trailer fields and TCP connection close
    else if ((length == 2) && !memcmp(msgText, "\r\n", 2)) {
        headers.length = STAT_NOTPRESENT;
    }
    // Normal case with trailer fields and TCP connection close
    else if ((length >= 5) && !memcmp(msgText+length-4, "\r\n\r\n", 4)) {
        headers.start = msgText;
        headers.length = length - 4;
    }
    // Abnormal cases truncated by TCP connection close
    else {
        infractions |= INF_TRUNCATED;

        // Lone <CR>
        if ((length == 1) && (msgText[0] == '\r')) {
            headers.length = STAT_NOTPRESENT;
        }
        // Truncation occurred somewhere in the trailer fields
        else {
            headers.start = msgText;
            headers.length = length;
            // When present, remove partial <CR><LF><CR><LF> sequence from the very end
            if ((length > 4) && !memcmp(msgText+length-3, "\r\n\r", 3)) headers.length -= 3;
            else if ((length > 3) && !memcmp(msgText+length-2, "\r\n", 2)) headers.length -= 2;
            else if ((length > 2) && (msgText[length-1] == '\r')) headers.length -= 1;
        }
    }
}

void NHttpMsgTrailer::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

void NHttpMsgTrailer::printMessage(FILE *output) const {
    NHttpMsgSection::printMessageTitle(output, "trailer");
    NHttpMsgSharedHead::printMessageHead(output);
    NHttpMsgSection::printMessageWrapup(output);
}


void NHttpMsgTrailer::updateFlow() const {
    if (tcpClose) {
        sessionData->typeExpected[sourceId] = SEC_CLOSED;
        sessionData->halfReset(sourceId);
    }
    else {
        sessionData->typeExpected[sourceId] = SEC_HEADER;
        sessionData->halfReset(sourceId);
    }
}























