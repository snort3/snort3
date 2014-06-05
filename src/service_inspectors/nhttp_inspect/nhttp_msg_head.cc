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
//  @brief      NHttpMsgHeader class analyzes individual HTTP message headers.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_test_input.h"  // &&& temporary to support TCP close workaround
#include "nhttp_msg_head.h"

using namespace NHttpEnums;

// Reinitialize everything derived in preparation for analyzing a new message
void NHttpMsgHeader::initSection() {
    NHttpMsgSharedHead::initSection();
    startLine.length = STAT_NOTCOMPUTE;
    version.length = STAT_NOTCOMPUTE;
    versionId = VERS__NOTCOMPUTE;
    method.length = STAT_NOTCOMPUTE;
    methodId = METH__NOTCOMPUTE;
    uri.length = STAT_NOTCOMPUTE;
    statusCode.length = STAT_NOTCOMPUTE;
    statusCodeNum = STAT_NOTCOMPUTE;
    reasonPhrase.length = STAT_NOTCOMPUTE;
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgHeader::analyze() {
    NHttpMsgSharedHead::analyze();
    if (sourceId == SRC_CLIENT) {
        parseRequestLine();
        deriveMethodId();
    }
    else if (sourceId == SRC_SERVER) {
        parseStatusLine();
        deriveStatusCodeNum();
    }
    deriveVersionId();
}

// All we do here is separate the start line from the header fields.
// It is so complicated because 1) there might not be any header fields and 2) the message may have been truncated by a TCP connection close.
// The asserts are very useful in test mode because they pick up bad test case data that we are not designed to handle. Otherwise they should
// never go off unless PAF is broken and feeding us bad stuff.
void NHttpMsgHeader::parseWhole() {
    startLine.start = msgText;
    startLine.length = findCrlf(startLine.start, length, false);
    // findCrtl() guarentees that either the start line is the whole message or there must be at least two more characters and the first two are <CR><LF>.
    assert((length == startLine.length) || ((length >= startLine.length+2) && !memcmp(msgText + startLine.length, "\r\n", 2)));

// &&& The else clause is a workaround for the lack of TCP close notification support in the framework.
// &&& Eventually the contents of the if clause should become the only code and the if-statement should go away.
if (NHttpTestInput::test_mode) {
    // We trust PAF. !tcpClose guarentees that either there are exactly four more characters <CR><LF><CR><LF> or there are at least seven more characters
    // with the first two being <CR><LF> and the last four being <CR><LF><CR><LF>.
    assert(tcpClose ||
           ((length == startLine.length+4) && !memcmp(msgText + startLine.length, "\r\n\r\n", 4)) ||
           ((length >= startLine.length+7) && !memcmp(msgText + startLine.length, "\r\n", 2) && !memcmp(msgText + length - 4, "\r\n\r\n", 4)));
}
else {
    // We trust PAF. Therefore if the invariants don't hold it must be because we got the leftovers after a TCP close.
    // So we kludge the close notification as a workaround.
    if ( ! ( ((length == startLine.length+4) && !memcmp(msgText + startLine.length, "\r\n\r\n", 4)) ||
             ((length >= startLine.length+7) && !memcmp(msgText + startLine.length, "\r\n", 2) && !memcmp(msgText + length - 4, "\r\n\r\n", 4)) ) ) tcpClose = true;
}

    // The following if-else ladder puts the extremely common normal cases at the beginning and the rare pathological cases at the end
    // Normal case with header fields
    if (!tcpClose && (length >= startLine.length+7)) {
        headers.start = msgText + startLine.length + 2;
        headers.length = length - startLine.length - 6;
    }
    // Normal case no header fields (only a start line)
    else if (!tcpClose) {
        headers.length = STAT_NOTPRESENT;
    }
    // Normal case with header fields and TCP connection close
    else if ((length >= startLine.length+7) && !memcmp(msgText+length-4, "\r\n\r\n", 4)) {
        headers.start = msgText + startLine.length + 2;
        headers.length = length - startLine.length - 6;
    }
    // Normal case no header fields and TCP connection close
    else if ((length == startLine.length + 4) && !memcmp(msgText+length-2, "\r\n", 2)) {
        headers.length = STAT_NOTPRESENT;
    }
    // Abnormal cases truncated by TCP connection close
    else {
        infractions |= INF_TRUNCATED;
        // Either start line incomplete or start line complete but no leftover octets for anything else
        if (length <= startLine.length+2) {
            headers.length = STAT_NOTPRESENT;
        }
        // Start line complete followed by lone <CR>
        else if ((length == startLine.length+3) && (msgText[length-1] == '\r')) {
            headers.length = STAT_NOTPRESENT;
        }
        // Truncation occurred somewhere in the header fields
        else {
            headers.start = msgText + startLine.length + 2;
            headers.length = length - startLine.length - 2;
            // When present, remove partial <CR><LF><CR><LF> sequence from the very end
            if ((length > startLine.length+6) && !memcmp(msgText+length-3, "\r\n\r", 3)) headers.length -= 3;
            else if ((length > startLine.length+5) && !memcmp(msgText+length-2, "\r\n", 2)) headers.length -= 2;
            else if ((length > startLine.length+4) && (msgText[length-1] == '\r')) headers.length -= 1;
        }
    }
}

void NHttpMsgHeader::parseRequestLine() {
    // There should be exactly two spaces. One following the method and one before "HTTP/".
    // Eventually we may need to cater to certain format errors, but for now exact match or treat as error.
    // <method><SP><URI><SP>HTTP/X.Y
    if (startLine.start[startLine.length-9] != ' ') {
        // space before "HTTP" missing or in wrong place
        infractions |= INF_BADREQLINE;
        return;
    }

    int space = -1;
    for (int32_t k=0; k < startLine.length-9; k++) {
        if (startLine.start[k] == ' ') {
            if (space == -1) space = k;
            else {
                // too many spaces
                infractions |= INF_BADREQLINE;
                return;
            }
        }
    }
    if ((space <= 0)) {
        // no first space or a leading space
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

void NHttpMsgHeader::parseStatusLine() {
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

void NHttpMsgHeader::deriveStatusCodeNum() {
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

void NHttpMsgHeader::deriveVersionId() {
    if (version.length != 8) {
        versionId = VERS__PROBLEMATIC;
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

void NHttpMsgHeader::deriveMethodId() {
    methodId = (MethodId) strToCode(method.start, method.length, methodList);
}

void NHttpMsgHeader::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

void NHttpMsgHeader::printMessage(FILE *output) const {
    NHttpMsgSection::printMessageTitle(output, "header");

    if (sourceId != SRC__NOTCOMPUTE) fprintf(output, "Source Id: %d\n", sourceId);
    if (versionId != VERS__NOTCOMPUTE) fprintf(output, "Version Id: %d\n", versionId);
    if (methodId != METH__NOTCOMPUTE) fprintf(output, "Method Id: %d\n", methodId);
    if (statusCodeNum != STAT_NOTCOMPUTE) fprintf(output, "Status Code Num: %d\n", statusCodeNum);
    printInterval(output, "Reason Phrase", reasonPhrase.start, reasonPhrase.length);
    printInterval(output, "URI", uri.start, uri.length);

    NHttpMsgSharedHead::printMessageHead(output);
    NHttpMsgSection::printMessageWrapup(output);
}


void NHttpMsgHeader::updateFlow() const {
    const uint64_t disasterMask = INF_BADREQLINE | INF_BADSTATLINE | INF_BROKENCHUNK | INF_BADCHUNKSIZE;

    // The following logic to determine body type is by no means the last word on this topic.
    if (tcpClose) {
        sessionData->typeExpected[sourceId] = SEC_CLOSED;
        sessionData->halfReset(sourceId);
    }
    else if (infractions & disasterMask) {
        sessionData->typeExpected[sourceId] = SEC_ABORT;
        sessionData->halfReset(sourceId);
    }
    else if ((sourceId == SRC_SERVER) && ((statusCodeNum <= 199) || (statusCodeNum == 204) || (statusCodeNum == 304))) {
        // No body allowed by RFC for these response codes
        sessionData->typeExpected[sourceId] = SEC_HEADER;
        sessionData->halfReset(sourceId);
    }
    // If there is a Transfer-Encoding header, see if the last of the encoded values is "chunked".
    else if ( (headerValueNorm[HEAD_TRANSFER_ENCODING].length > 0) &&
         ((*(int64_t *)(headerValueNorm[HEAD_TRANSFER_ENCODING].start + (headerValueNorm[HEAD_TRANSFER_ENCODING].length - 8))) == TRANSCODE_CHUNKED) ) {
        // Chunked body
        sessionData->typeExpected[sourceId] = SEC_CHUNKHEAD;
        sessionData->bodySections[sourceId] = 0;
        sessionData->bodyOctets[sourceId] = 0;
        sessionData->numChunks[sourceId] = 0;
    }
    else if ((headerValueNorm[HEAD_CONTENT_LENGTH].length > 0) && (*(int64_t*)headerValueNorm[HEAD_CONTENT_LENGTH].start > 0)) {
        // Regular body
        sessionData->typeExpected[sourceId] = SEC_BODY;
        sessionData->octetsExpected[sourceId] = *(int64_t*)headerValueNorm[HEAD_CONTENT_LENGTH].start;
        sessionData->dataLength[sourceId] = *(int64_t*)headerValueNorm[HEAD_CONTENT_LENGTH].start;
        sessionData->bodySections[sourceId] = 0;
        sessionData->bodyOctets[sourceId] = 0;
    }
    else {
        // No body
        sessionData->typeExpected[sourceId] = SEC_HEADER;
        sessionData->halfReset(sourceId);
    }
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgHeader::legacyClients() const {
    NHttpMsgSharedHead::legacyClients();
    if (method.length > 0) SetHttpBuffer(HTTP_BUFFER_METHOD, method.start, (unsigned)method.length);
    if (uri.length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_URI, uri.start, (unsigned)uri.length);
    if (uri.length > 0) SetHttpBuffer(HTTP_BUFFER_URI, uri.start, (unsigned)uri.length);
    if (statusCode.length > 0) SetHttpBuffer(HTTP_BUFFER_STAT_CODE, statusCode.start, (unsigned)statusCode.length);
    if (reasonPhrase.length > 0) SetHttpBuffer(HTTP_BUFFER_STAT_MSG, reasonPhrase.start, (unsigned)reasonPhrase.length);
}





