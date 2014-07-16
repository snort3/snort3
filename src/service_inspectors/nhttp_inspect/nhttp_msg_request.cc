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
#include "nhttp_normalizers.h"
#include "nhttp_msg_request.h"

using namespace NHttpEnums;

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
    deriveMethodId();
    uri = new NHttpUri(startLine.start + method.length + 1, startLine.length - method.length - 10, methodId);
    version.start = startLine.start + (startLine.length - 8);
    version.length = 8;
    assert (startLine.length == method.length + uri->getUri().length + version.length + 2);
}

void NHttpMsgRequest::deriveMethodId() {
    if (method.length <= 0) {
        methodId = METH__NOSOURCE;
        return;
    }
    methodId = (MethodId) strToCode(method.start, method.length, methodList);
}

void NHttpMsgRequest::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

void NHttpMsgRequest::printSection(FILE *output) {
    NHttpMsgSection::printMessageTitle(output, "request line");
    fprintf(output, "Version Id: %d\n", versionId);
    fprintf(output, "Method Id: %d\n", methodId);
    printInterval(output, "URI", uri->getUri().start, uri->getUri().length);
    if ((uri->getUriType() != URI__NOTCOMPUTE) && (uri->getUriType() != URI__NOSOURCE)) fprintf(output, "URI Type: %d\n", uri->getUriType());
    printInterval(output, "Scheme", uri->getScheme().start, uri->getScheme().length);
    if ((uri->getSchemeId() != SCH__NOTCOMPUTE) && (uri->getSchemeId() != SCH__NOSOURCE)) fprintf(output, "Scheme Id: %d\n", uri->getSchemeId());
    printInterval(output, "Authority", uri->getAuthority().start, uri->getAuthority().length);
    printInterval(output, "Host Name", uri->getHost().start, uri->getHost().length);
    printInterval(output, "Normalized Host Name", uri->getNormHost().start, uri->getNormHost().length);
    printInterval(output, "Port", uri->getPort().start, uri->getPort().length);
    if ((uri->getPortValue() != STAT_NOTCOMPUTE) && (uri->getPortValue() != STAT_NOSOURCE)) fprintf(output, "Port Value: %d\n", uri->getPortValue());
    printInterval(output, "Absolute Path", uri->getAbsPath().start, uri->getAbsPath().length);
    printInterval(output, "Path", uri->getPath().start, uri->getPath().length);
    printInterval(output, "Normalized Path", uri->getNormPath().start, uri->getNormPath().length);
    printInterval(output, "Query", uri->getQuery().start, uri->getQuery().length);
    printInterval(output, "Normalized Query", uri->getNormQuery().start, uri->getNormQuery().length);
    printInterval(output, "Fragment", uri->getFragment().start, uri->getFragment().length);
    printInterval(output, "Normalized Fragment", uri->getNormFragment().start, uri->getNormFragment().length);
    fprintf(output, "URI infractions: overall %" PRIx64 ", host %" PRIx64 ", path %" PRIx64 ", query %" PRIx64 ", fragment %" PRIx64 "\n",
       uri->getUriInfractions(), uri->getHostInfractions(), uri->getPathInfractions(), uri->getQueryInfractions(),
       uri->getFragmentInfractions());
    NHttpMsgSection::printMessageWrapup(output);
 }

void NHttpMsgRequest::updateFlow() {
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
        sessionData->methodId[sourceId] = methodId;
    }
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgRequest::legacyClients() {
    ClearHttpBuffers();
    if (method.length > 0) SetHttpBuffer(HTTP_BUFFER_METHOD, method.start, (unsigned)method.length);
    if (uri->getUri().length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_URI, uri->getUri().start, (unsigned)uri->getUri().length);
    if (uri->getNormLegacy().length > 0) SetHttpBuffer(HTTP_BUFFER_URI, uri->getNormLegacy().start, (unsigned)uri->getNormLegacy().length);
}




