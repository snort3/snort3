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
//  @brief      NHttpMsgStatus class analyzes HTTP status line
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_header.h"

using namespace NHttpEnums;

NHttpMsgStatus::NHttpMsgStatus(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, SourceId sourceId_) :
       NHttpMsgStart(buffer, bufSize, sessionData_, sourceId_), request(sessionData->requestLine) {
    delete sessionData->statusLine;
    sessionData->statusLine = this;
    delete sessionData->headers[SRC_SERVER];
    sessionData->headers[SRC_SERVER] = nullptr;
    delete sessionData->latestOther[SRC_SERVER];
    sessionData->latestOther[SRC_SERVER] = nullptr;
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgStatus::analyze() {
    NHttpMsgStart::analyze();
    deriveStatusCodeNum();
}

void NHttpMsgStatus::parseStartLine() {
    // Eventually we may need to cater to certain format errors, but for now exact match or treat as error.
    // HTTP/X.Y<SP>###<SP><text>
    if ((startLine.length < 13) || (startLine.start[8] != ' ') || (startLine.start[12] != ' ')) {
        infractions |= INF_BADSTATLINE;
        return;
    }
    version.start = startLine.start;
    version.length = 8;
    statusCode.start = startLine.start + 9;
    statusCode.length = 3;
    reasonPhrase.start = startLine.start + 13;
    reasonPhrase.length = startLine.length - 13;
    for (int32_t k = 0; k < reasonPhrase.length; k++) {
        if ((reasonPhrase.start[k] <= 31) || (reasonPhrase.start[k] >= 127)) {
            // Illegal character in reason phrase
            infractions |= INF_BADPHRASE;
            break;
        }
    }
    assert (startLine.length == version.length + statusCode.length + reasonPhrase.length + 2);
}

void NHttpMsgStatus::deriveStatusCodeNum() {
    if (statusCode.length <= 0) {
        statusCodeNum = STAT_NOSOURCE;
        return;
    }
    if (statusCode.length != 3) {
        statusCodeNum = STAT_PROBLEMATIC;
        return;
    }

    if ((statusCode.start[0] < '0') || (statusCode.start[0] > '9') || (statusCode.start[1] < '0') || (statusCode.start[1] > '9') ||
       (statusCode.start[2] < '0') || (statusCode.start[2] > '9')) {
        infractions |= INF_BADSTATCODE;
        statusCodeNum = STAT_PROBLEMATIC;
        return;
    }
    statusCodeNum = (statusCode.start[0] - '0') * 100 + (statusCode.start[1] - '0') * 10 + (statusCode.start[2] - '0');
    if ((statusCodeNum < 100) || (statusCodeNum > 599)) {
        infractions |= INF_BADSTATCODE;
    }
}

void NHttpMsgStatus::genEvents() {}

void NHttpMsgStatus::printSection(FILE *output) {
    NHttpMsgSection::printMessageTitle(output, "status line");
    fprintf(output, "Version Id: %d\n", versionId);
    fprintf(output, "Status Code Num: %d\n", statusCodeNum);
    reasonPhrase.print(output, "Reason Phrase");
    NHttpMsgSection::printMessageWrapup(output);
}

void NHttpMsgStatus::updateFlow() {
    const uint64_t disasterMask = INF_BADSTATLINE;

    // The following logic to determine body type is by no means the last word on this topic.
    if (tcpClose) {
        sessionData->typeExpected[sourceId] = SEC_CLOSED;
        sessionData->halfReset(sourceId);
    }
    else if (infractions & disasterMask) {
        sessionData->typeExpected[sourceId] = SEC_ABORT;
        sessionData->halfReset(sourceId);
    }
    else {
        sessionData->typeExpected[sourceId] = SEC_HEADER;
        sessionData->versionId[sourceId] = versionId;
        sessionData->statusCodeNum[sourceId] = statusCodeNum;
    }
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgStatus::legacyClients() {
    ClearHttpBuffers();
    if ((request != nullptr) && (request->getMethod().length > 0)) {
        SetHttpBuffer(HTTP_BUFFER_METHOD, request->getMethod().start, (unsigned)request->getMethod().length);
    }
    if ((request != nullptr) && (request->getUri().length > 0)) {
        SetHttpBuffer(HTTP_BUFFER_RAW_URI, request->getUri().start, (unsigned)request->getUri().length);
    }
    if ((request != nullptr) && (request->getUriNormLegacy().length > 0)) {
        SetHttpBuffer(HTTP_BUFFER_URI, request->getUriNormLegacy().start, (unsigned)request->getUriNormLegacy().length);
    }
    if (statusCode.length > 0) {
        SetHttpBuffer(HTTP_BUFFER_STAT_CODE, statusCode.start, (unsigned)statusCode.length);
    }
    if (reasonPhrase.length > 0) {
        SetHttpBuffer(HTTP_BUFFER_STAT_MSG, reasonPhrase.start, (unsigned)reasonPhrase.length);
    }
}





