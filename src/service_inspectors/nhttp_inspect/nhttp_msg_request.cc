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
//  @brief      NHttpMsgRequest class analyzes individual HTTP request line.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_request.h"

using namespace NHttpEnums;

// Reinitialize everything derived in preparation for analyzing a new message
void NHttpMsgRequest::initSection() {
    NHttpMsgStart::initSection();
    method.length = STAT_NOTCOMPUTE;
    uri.length = STAT_NOTCOMPUTE;
}

// All the processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgRequest::analyze() {
    NHttpMsgStart::analyze();
    deriveMethodId();
}

void NHttpMsgRequest::parseStartLine() {
    // There should be exactly two spaces. One following the method and one before "HTTP/".
    // Additional spaces located within the URI are not allowed but we will tolerate it
    // <method><SP><URI><SP>HTTP/X.Y
    if (startLine.start[startLine.length-9] != ' ') {
        // space before "HTTP" missing or in wrong place
        infractions |= INF_BADREQLINE;
        return;
    }

    int32_t space;
    for (space = 0; space < startLine.length-9; space++) {
        if (startLine.start[space] == ' ') break;
    }
    if (space >= startLine.length-9) {
        // leading space or no space
        infractions |= INF_BADREQLINE;
        return;
    }

    method.start = startLine.start;
    method.length = space;
    uri.start = startLine.start + method.length + 1;
    uri.length = startLine.length - method.length - 10;
    version.start = startLine.start + (startLine.length - 8);
    version.length = 8;
    assert (startLine.length == method.length + uri.length + version.length + 2);
}

void NHttpMsgRequest::deriveMethodId() {
    methodId = (MethodId) strToCode(method.start, method.length, methodList);
}

void NHttpMsgRequest::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

void NHttpMsgRequest::printSection(FILE *output) const {
    NHttpMsgSection::printMessageTitle(output, "request line");
    if (versionId != VERS__NOTCOMPUTE) fprintf(output, "Version Id: %d\n", versionId);
    if (methodId != METH__NOTCOMPUTE) fprintf(output, "Method Id: %d\n", methodId);
    printInterval(output, "URI", uri.start, uri.length);
    NHttpMsgSection::printMessageWrapup(output);
}

void NHttpMsgRequest::updateFlow() const {
    const uint64_t disasterMask = INF_BADREQLINE;

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
        sessionData->methodId = methodId;
    }
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgRequest::legacyClients() const {
    if (method.length > 0) SetHttpBuffer(HTTP_BUFFER_METHOD, method.start, (unsigned)method.length);
    if (uri.length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_URI, uri.start, (unsigned)uri.length);
    if (uri.length > 0) SetHttpBuffer(HTTP_BUFFER_URI, uri.start, (unsigned)uri.length);
}





