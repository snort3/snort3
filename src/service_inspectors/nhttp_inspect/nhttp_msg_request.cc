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

const UriNormalizer NHttpMsgRequest::uriNoPath { false };
const UriNormalizer NHttpMsgRequest::uriPath { true };

// Reinitialize everything derived in preparation for analyzing a new message
void NHttpMsgRequest::initSection() {
    NHttpMsgStart::initSection();
    method.length = STAT_NOTCOMPUTE;
    uri.length = STAT_NOTCOMPUTE;
    uriLegacyNorm.length = STAT_NOTCOMPUTE;
    uriType = URI__NOTCOMPUTE;
    scheme.length = STAT_NOTCOMPUTE;
    schemeId = SCH__NOTCOMPUTE;
    host.length = STAT_NOTCOMPUTE;
    hostInfractions = 0;
    hostNorm.length = STAT_NOTCOMPUTE;
    port.length = STAT_NOTCOMPUTE;
    portValue = STAT_NOTCOMPUTE;
    path.length = STAT_NOTCOMPUTE;
    pathInfractions = 0;
    pathNorm.length = STAT_NOTCOMPUTE;
    query.length = STAT_NOTCOMPUTE;
    queryInfractions = 0;
    queryNorm.length = STAT_NOTCOMPUTE;
    fragment.length = STAT_NOTCOMPUTE;
    fragmentInfractions = 0;
    fragmentNorm.length = STAT_NOTCOMPUTE;
}

// All the processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgRequest::analyze() {
    NHttpMsgStart::analyze();
    deriveMethodId();
    parseUri();
    deriveSchemeId();
    parseAuthority();
    derivePortValue();
    parseAbsPath();
    uriPath.normalize(path, pathNorm, scratchPad, pathInfractions);
    uriNoPath.normalize(host, hostNorm, scratchPad, hostInfractions);
    uriNoPath.normalize(query, queryNorm, scratchPad, queryInfractions);
    uriNoPath.normalize(fragment, fragmentNorm, scratchPad, fragmentInfractions);
    makeLegacyNormUri();
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

void NHttpMsgRequest::parseUri() {
    if (uriType != URI__NOTCOMPUTE) return;
    if (uri.length <= 0) {
        uriType = URI__NOTPRESENT;
        return;
    }

    // Four basic types of HTTP URI
    // "*" means request does not apply to any specific resource
    if ((uri.length == 1) && (uri.start[0] == '*')) {
        uriType = URI_ASTERISK;
        scheme.length = STAT_NOTPRESENT;
        authority.length = STAT_NOTPRESENT;
        absPath.length = STAT_NOTPRESENT;
    }
    // CONNECT method uses an authority
    else if (methodId == METH_CONNECT) {
        uriType = URI_AUTHORITY;
        scheme.length = STAT_NOTPRESENT;
        authority.length = uri.length;
        authority.start = uri.start;
        absPath.length = STAT_NOTPRESENT;
    }
    // Absolute path is a path but no scheme or authority
    else if (uri.start[0] == '/') {
        uriType = URI_ABSPATH;
        scheme.length = STAT_NOTPRESENT;
        authority.length = STAT_NOTPRESENT;
        absPath.length = uri.length;
        absPath.start = uri.start;
    }
    // Absolute URI includes scheme, authority, and path
    else {
        // Find the "://" and then the "/"
        int j;
        int k;
        for (j = 0; (uri.start[j] != ':') && (j < uri.length); j++);
        for (k = j+3; (uri.start[k] != '/') && (k < uri.length); k++);
        if ((k < uri.length) && (uri.start[j+1] == '/') && (uri.start[j+2] == '/')) {
            uriType = URI_ABSOLUTE;
            scheme.length = j;
            scheme.start = uri.start;
            authority.length = k - j - 3;
            authority.start = uri.start + j + 3;
            absPath.length = uri.length - k;
            absPath.start = uri.start + k;
        }
        else {
            infractions |= INF_BADURI;
            uriType = URI__PROBLEMATIC;
            scheme.length = STAT_PROBLEMATIC;
            authority.length = STAT_PROBLEMATIC;
            absPath.length = STAT_PROBLEMATIC;
        }
    }
}

void NHttpMsgRequest::deriveSchemeId() {
    if (schemeId != SCH__NOTCOMPUTE) return;
    if (scheme.length <= 0) return;

    // Normalize scheme name to lower case for matching purposes
    uint8_t *lowerScheme;
    if ((lowerScheme = scratchPad.request(scheme.length)) == nullptr) {
        infractions |= INF_NOSCRATCH;
        schemeId = SCH__INSUFMEMORY;
        return;
    }
    norm2Lower(scheme.start, scheme.length, lowerScheme, infractions, nullptr);
    schemeId = (SchemeId) strToCode(lowerScheme, scheme.length, schemeList);
}

void NHttpMsgRequest::parseAuthority() {
    if (host.length != STAT_NOTCOMPUTE) return;
    if (authority.length <= 0) return;
    host.start = authority.start;
    for (host.length = 0; (authority.start[host.length] != ':') && (host.length < authority.length); host.length++);
    if (host.length < authority.length) {
        port.length = authority.length - host.length - 1;
        port.start = authority.start + host.length + 1;
    }
    else port.length = STAT_NOTPRESENT;
}

void NHttpMsgRequest::derivePortValue() {
    if (portValue != SCH__NOTCOMPUTE) return;
    if (port.length <= 0) return;
    portValue = 0;
    for (int k = 0; k < port.length; k++) {
        portValue = portValue * 10 + (port.start[k] - '0');
        if ((port.start[k] < '0') || (port.start[k] > '9') || (portValue > 65535))
        {
            infractions |= INF_BADPORT;
            portValue = STAT_PROBLEMATIC;
            break;
        }
    }
}

void NHttpMsgRequest::parseAbsPath() {
    if (path.length != STAT_NOTCOMPUTE) return;
    if (absPath.length <= 0) return;
    path.start = absPath.start;
    for (path.length = 0; (absPath.start[path.length] != '?') && (absPath.start[path.length] != '#') && (path.length < absPath.length); path.length++);
    if (path.length == absPath.length) {
        query.length = STAT_NOTPRESENT;
        fragment.length = STAT_NOTPRESENT;
        return;
    }
    if (absPath.start[path.length] == '?') {
        query.start = absPath.start + path.length + 1;
        for (query.length = 0; (query.start[query.length] != '#') && (query.length < absPath.length - path.length - 1); query.length++);
        fragment.start = query.start + query.length + 1;
        fragment.length = absPath.length - path.length - 1 - query.length - 1;
    }
    else {
        query.length = STAT_NOTPRESENT;
        fragment.start = absPath.start + path.length + 1;
        fragment.length = absPath.length - path.length - 1;
    }
}

void NHttpMsgRequest::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

void NHttpMsgRequest::printSection(FILE *output) const {
    NHttpMsgSection::printMessageTitle(output, "request line");
    if (versionId != VERS__NOTCOMPUTE) fprintf(output, "Version Id: %d\n", versionId);
    if (methodId != METH__NOTCOMPUTE) fprintf(output, "Method Id: %d\n", methodId);
    printInterval(output, "URI", uri.start, uri.length);
    if (uriType != URI__NOTCOMPUTE) fprintf(output, "URI Type: %d\n", uriType);
    printInterval(output, "Scheme", scheme.start, scheme.length);
    if (schemeId != SCH__NOTCOMPUTE) fprintf(output, "Scheme Id: %d\n", schemeId);
    printInterval(output, "Authority", authority.start, authority.length);
    printInterval(output, "Host Name", host.start, host.length);
    printInterval(output, "Normalized Host Name", hostNorm.start, hostNorm.length);
    printInterval(output, "Port", port.start, port.length);
    if (portValue != STAT_NOTCOMPUTE) fprintf(output, "Port Value: %d\n", portValue);
    printInterval(output, "Absolute Path", absPath.start, absPath.length);
    printInterval(output, "Path", path.start, path.length);
    printInterval(output, "Normalized Path", pathNorm.start, pathNorm.length);
    printInterval(output, "Query", query.start, query.length);
    printInterval(output, "Normalized Query", queryNorm.start, queryNorm.length);
    printInterval(output, "Fragment", fragment.start, fragment.length);
    printInterval(output, "Normalized Fragment", fragmentNorm.start, fragmentNorm.length);
    fprintf(output, "URI infractions: host %" PRIx64 ", path %" PRIx64 ", query %" PRIx64 ", fragment %" PRIx64 "\n",
       hostInfractions, pathInfractions, queryInfractions, fragmentInfractions);
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
        sessionData->methodId[sourceId] = methodId;
        sessionData->schemeId[sourceId] = schemeId;
    }
}

// Glue normalized URI fields back together 
void NHttpMsgRequest::makeLegacyNormUri() {
    if (uriLegacyNorm.length != STAT_NOTCOMPUTE) return;

    // We can reuse the raw URI for the normalized URI unless at least one part of the URI has been normalized
    if ((hostInfractions == 0) && (pathInfractions == 0) && (queryInfractions == 0) && (fragmentInfractions == 0)) {
        uriLegacyNorm.start = uri.start;
        uriLegacyNorm.length = uri.length;
        return;
    }

    // Glue normalized path pieces back together
    const uint32_t totalLength = ((scheme.length >= 0) ? scheme.length + 3 : 0) +
                                 ((hostNorm.length >= 0) ? hostNorm.length : 0) +
                                 ((port.length >= 0) ? port.length + 1 : 0) +
                                 ((pathNorm.length >= 0) ? pathNorm.length : 0) +
                                 ((queryNorm.length >= 0) ? queryNorm.length + 1 : 0) +
                                 ((fragmentNorm.length >= 0) ? fragmentNorm.length + 1 : 0);
    uint8_t* const scratch = scratchPad.request(totalLength);
    if (scratch != nullptr) {
        uint8_t *current = scratch;
        if (scheme.length >= 0) {
            memcpy(current, scheme.start, scheme.length);
            current += scheme.length;
            memcpy(current, "://", 3);
            current += 3;
        }
        if (hostNorm.length >= 0) {
            memcpy(current, hostNorm.start, hostNorm.length);
            current += hostNorm.length;
        }
        if (port.length >= 0) {
            memcpy(current, ":", 1);
            current += 1;
            memcpy(current, port.start, port.length);
            current += port.length;
        }
        if (pathNorm.length >= 0) {
            memcpy(current, pathNorm.start, pathNorm.length);
            current += pathNorm.length;
        }
        if (queryNorm.length >= 0) {
            memcpy(current, "?", 1);
            current += 1;
            memcpy(current, queryNorm.start, queryNorm.length);
            current += queryNorm.length;
        }
        if (fragmentNorm.length >= 0) {
            memcpy(current, "#", 1);
            current += 1;
            memcpy(current, fragmentNorm.start, fragmentNorm.length);
            current += fragmentNorm.length;
        }
        assert(totalLength == current - scratch);
        scratchPad.commit(current - scratch);
        uriLegacyNorm.start = scratch;
        uriLegacyNorm.length = current - scratch;
    }
    else uriLegacyNorm.length = STAT_INSUFMEMORY;
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgRequest::legacyClients() const {
    ClearHttpBuffers();
    if (method.length > 0) SetHttpBuffer(HTTP_BUFFER_METHOD, method.start, (unsigned)method.length);
    if (uri.length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_URI, uri.start, (unsigned)uri.length);
    if (uriLegacyNorm.length > 0) SetHttpBuffer(HTTP_BUFFER_URI, uriLegacyNorm.start, (unsigned)uriLegacyNorm.length);
}




