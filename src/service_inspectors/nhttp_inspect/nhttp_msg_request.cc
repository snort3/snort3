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
    if (methodId == METH__OTHER) createEvent(EVENT_UNKNOWN_METHOD);

    // URI character encoding events
    if (uri && (uri->getUriInfractions() & INF_URIPERCENTASCII)) createEvent(EVENT_ASCII);
    if (uri && (uri->getUriInfractions() & INF_URIPERCENTUCODE)) createEvent(EVENT_U_ENCODE);
    if (uri && (uri->getUriInfractions() & INF_URI8BITCHAR)) createEvent(EVENT_BARE_BYTE);
    if (uri && (uri->getUriInfractions() & INF_URIPERCENTUTF8)) createEvent(EVENT_UTF_8);
    if (uri && (uri->getUriInfractions() & INF_URIBADCHAR)) createEvent(EVENT_NON_RFC_CHAR);

    // URI path events
    if (uri && (uri->getPathInfractions() & INF_URIMULTISLASH)) createEvent(EVENT_MULTI_SLASH);
    if (uri && (uri->getPathInfractions() & INF_URIBACKSLASH)) createEvent(EVENT_IIS_BACKSLASH);
    if (uri && (uri->getPathInfractions() & INF_URISLASHDOT)) createEvent(EVENT_SELF_DIR_TRAV);
    if (uri && (uri->getPathInfractions() & INF_URISLASHDOTDOT)) createEvent(EVENT_DIR_TRAV);
    if (uri && (uri->getPathInfractions() & INF_URIROOTTRAV)) createEvent(EVENT_WEBROOT_DIR);

}

void NHttpMsgRequest::printSection(FILE *output) {
    NHttpMsgSection::printMessageTitle(output, "request line");
    fprintf(output, "Version Id: %d\n", versionId);
    fprintf(output, "Method Id: %d\n", methodId);
    uri->getUri().print(output, "URI");
    if (uri->getUriType() != URI__NOSOURCE) fprintf(output, "URI Type: %d\n", uri->getUriType());
    uri->getScheme().print(output, "Scheme");
    if (uri->getSchemeId() != SCH__NOSOURCE) fprintf(output, "Scheme Id: %d\n", uri->getSchemeId());
    uri->getAuthority().print(output, "Authority");
    uri->getHost().print(output, "Host Name");
    uri->getNormHost().print(output, "Normalized Host Name");
    uri->getPort().print(output, "Port");
    if (uri->getPortValue() != STAT_NOSOURCE) fprintf(output, "Port Value: %d\n", uri->getPortValue());
    uri->getAbsPath().print(output, "Absolute Path");
    uri->getPath().print(output, "Path");
    uri->getNormPath().print(output, "Normalized Path");
    uri->getQuery().print(output, "Query");
    uri->getNormQuery().print(output, "Normalized Query");
    uri->getFragment().print(output, "Fragment");
    uri->getNormFragment().print(output, "Normalized Fragment");
    fprintf(output, "URI infractions: overall %" PRIx64 ", format %" PRIx64 ", scheme %" PRIx64 ", host %" PRIx64 ", port %" PRIx64 ", path %"
       PRIx64 ", query %" PRIx64 ", fragment %" PRIx64 "\n",
       uri->getUriInfractions(), uri->getFormatInfractions(), uri->getSchemeInfractions(), uri->getHostInfractions(),
       uri->getPortInfractions(), uri->getPathInfractions(), uri->getQueryInfractions(), uri->getFragmentInfractions());
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




