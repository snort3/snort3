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
//  @brief      NHttpMsgHeader class analyzes individual HTTP messages.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "flow/flow.h"
#include "detection/detection_util.h"
#include "nhttp_enum.h"
#include "nhttp_scratchpad.h"
#include "nhttp_strtocode.h"
#include "nhttp_headnorm.h"
#include "nhttp_flowdata.h"
#include "nhttp_msgheader.h"

using namespace NHttpEnums;

// Return the number of octets before the first CRLF. Return length if CRLF not present.
//
// wrappable: CRLF does not count in a header field when immediately followed by <SP> or <LF>. These whitespace characters
// at the beginning of the next line indicate that the previous header has wrapped and is continuing on the next line.
uint32_t NHttpMsgHeader::findCrlf(const uint8_t* buffer, uint32_t length, bool wrappable) {
    for (uint32_t k=0; k < length-1; k++) {
        if ((buffer[k] == '\r') && (buffer[k+1] == '\n'))
            if (!wrappable || (k+2 >= length) || ((buffer[k+2] != ' ') && (buffer[k+2] != '\t'))) return k;
    }
    return length;
}

// Reinitialize everything and load a new message
void NHttpMsgHeader::loadMessage(const uint8_t *buffer, const uint16_t bufsize, NHttpFlowData *sessionData_) {
    length = (bufsize <= MAXOCTETS) ? bufsize : MAXOCTETS;
    memcpy(rawBuf, buffer, length);

    sessionData = sessionData_;
    infractions = sessionData->infractions;
    sourceId = sessionData->sourceId;
    tcpClose = sessionData->tcpClose;

    scratchPad.reinit();

    startLine.length = STAT_NOTCOMPUTE;
    version.length = STAT_NOTCOMPUTE;
    versionId = VERS__NOTCOMPUTE;
    method.length = STAT_NOTCOMPUTE;
    methodId = METH__NOTCOMPUTE;
    uri.length = STAT_NOTCOMPUTE;
    statusCode.length = STAT_NOTCOMPUTE;
    statusCodeNum = STAT_NOTCOMPUTE;
    reasonPhrase.length = STAT_NOTCOMPUTE;
    headers.length = STAT_NOTCOMPUTE;
    numHeaders = STAT_NOTCOMPUTE;
    for(int k = 0; k < MAXHEADERS; k++) {
        headerLine[k].length = STAT_NOTCOMPUTE;
        headerName[k].length = STAT_NOTCOMPUTE;
        headerNameId[k] = HEAD__NOTCOMPUTE;
        headerValue[k].length = STAT_NOTCOMPUTE;
    }
    for (int k = 1; k < HEAD__MAXVALUE; k++) {
        headerValueNorm[k].length = STAT_NOTCOMPUTE;
    }
}

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgHeader::analyze() {
    parseWhole();
    if (sourceId == SRC_CLIENT) {
        parseRequestLine();
        deriveMethodId();
    }
    else if (sourceId == SRC_SERVER) {
        parseStatusLine();
        deriveStatusCodeNum();
    }
    deriveVersionId();
    parseHeaderBlock();
    parseHeaderLines();
    for (int j=0; j < MAXHEADERS; j++) {
        if (headerName[j].length <= 0) break;
        deriveHeaderNameId(j);
    }
    for (int k=1; k <= numNorms; k++) {
        headerNorms[k]->normalize(scratchPad, infractions, (HeaderId)k, headerNameId, headerValue, MAXHEADERS, headerValueNorm[k]);
    }
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
    // We trust PAF. !tcpClose guarentees that either there are exactly four more characters <CR><LF><CR><LF> or there are at least seven more characters
    // with the first two being <CR><LF> and the last four being <CR><LF><CR><LF>.
    assert(tcpClose ||
           ((length == startLine.length+4) && !memcmp(msgText + startLine.length, "\r\n\r\n", 4)) ||
           ((length >= startLine.length+7) && !memcmp(msgText + startLine.length, "\r\n", 2) && !memcmp(msgText + length - 4, "\r\n\r\n", 4)));

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
    assert (startLine.length == version.length + statusCode.length + reasonPhrase.length + 2);
}

// Divide up the block of header fields into individual header field lines.
void NHttpMsgHeader::parseHeaderBlock() {
    if (headers.length <= 0) return;
    int32_t bytesused = 0;
    numHeaders = 0;
    while (bytesused < headers.length) {
        headerLine[numHeaders].start = headers.start + bytesused;
        headerLine[numHeaders].length = findCrlf(headerLine[numHeaders].start, headers.length - bytesused, true);
        bytesused += headerLine[numHeaders++].length + 2;
        if (numHeaders >= MAXHEADERS) {
             break;
        }
    }
    if (bytesused < headers.length) {
        infractions |= INF_TOOMANYHEADERS;
    }
}

// Divide header field lines into field name and field value
void NHttpMsgHeader::parseHeaderLines() {
    int colon;
    for (int k=0; k < numHeaders; k++) {
        for (colon=0; colon < headerLine[k].length; colon++) {
            if (headerLine[k].start[colon] == ':') break;
        }
        if (colon < headerLine[k].length) {
            headerName[k].start = headerLine[k].start;
            headerName[k].length = colon;
            headerValue[k].start = headerLine[k].start + colon + 1;
            headerValue[k].length = headerLine[k].length - colon - 1;
        }
        else {
            infractions |= INF_BADHEADER;
        }
    }
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

void NHttpMsgHeader::deriveHeaderNameId(int index) {
     if (headerName[index].length <= 0) return;
    // Normalize header field name to lower case for matching purposes
    uint8_t *lowerName;
    if ((lowerName = scratchPad.request(headerName[index].length)) == nullptr) {
        infractions |= INF_NOSCRATCH;
        headerNameId[index] = HEAD__INSUFMEMORY;
        return;
    }
    int32_t lowerLength = norm2Lower(headerName[index].start, headerName[index].length, lowerName, infractions, nullptr);
    headerNameId[index] = (HeaderId) strToCode(lowerName, lowerLength, headerList);
}

void NHttpMsgHeader::genEvents() {
    if (infractions != 0) SnortEventqAdd(GID_HTTP_CLIENT, 1); // I'm just an example event (HI_CLIENT_ASCII)
}

void NHttpMsgHeader::printInterval(FILE *output, const char* name, const uint8_t *text, int32_t length, bool intVals) {
    if ((length == STAT_NOTPRESENT) || (length == STAT_NOTCOMPUTE)) return;
    fprintf(output, "%s, length = %d\n", name, length);
    if (length <= 0) return;
    if (text == nullptr) {
        fprintf(output, "nullptr\n");
        return;
    }
    for (int k=0; k < length; k++) {
        if ((text[k] >= 0x20) && (text[k] <= 0x7E)) fprintf(output, "%c", (char)text[k]);
        else if (text[k] == 0x0) fprintf(output, "~");
        else if (text[k] == 0xD) fprintf(output, "`");
        else if (text[k] == 0xA) fprintf(output, "'");
        else fprintf(output, "*");
        if (k%200 == 199) fprintf(output, "\n");
    }

    if (intVals && (length%4 == 0)) {
        fprintf(output, "\nInteger values =");
        for (int j=0; j < length; j+=4) {
            fprintf(output, " %u", *((const uint32_t*)(text+j)));
        }
    }
    fprintf(output, "\n");
}

void NHttpMsgHeader::printMessage(FILE *output) {
    fprintf(output, "Printout of HTTP message structure.\n");
    printInterval(output, "Raw message", msgText, length);
    printInterval(output, "Start Line", startLine.start, startLine.length);
    if (sourceId != SRC__NOTCOMPUTE) fprintf(output, "Source Id: %d\n", sourceId);
    printInterval(output, "Version", version.start, version.length);
    if (versionId != VERS__NOTCOMPUTE) fprintf(output, "Version Id: %d\n", versionId);
    printInterval(output, "Method", method.start, method.length);
    if (methodId != METH__NOTCOMPUTE) fprintf(output, "Method Id: %d\n", methodId);
    printInterval(output, "URI", uri.start, uri.length);
    printInterval(output, "Status Code", statusCode.start, statusCode.length);
    if (statusCodeNum != STAT_NOTCOMPUTE) fprintf(output, "Status Code Num: %d\n", statusCodeNum);
    printInterval(output, "Reason Phrase", reasonPhrase.start, reasonPhrase.length);
    printInterval(output, "Headers", headers.start, headers.length);
    if (numHeaders != STAT_NOTCOMPUTE) fprintf(output, "Number of headers: %d\n", numHeaders);
    for (int j=0; j < numHeaders && j < 200; j++) {
        printInterval(output, "Header Line", headerLine[j].start, headerLine[j].length);
        printInterval(output, "Header Name", headerName[j].start, headerName[j].length);
        fprintf(output, "Header name Id: %d\n", headerNameId[j]);
        printInterval(output, "Header Value", headerValue[j].start, headerValue[j].length);
    }
    for (int k=1; k <= numNorms; k++) {
        if (headerValueNorm[k].length != STAT_NOTPRESENT) fprintf(output, "Header ID = %d\n", k);
        printInterval(output, "Header Value Normalized", headerValueNorm[k].start, headerValueNorm[k].length, true);
    }
    fprintf(output, "Infractions: %lx\n", infractions);
    fprintf(output, "TCP Close: %s\n", tcpClose ? "True" : "False");

    fprintf(output, "Interface to old clients. http_mask = %x.\n", http_mask);
    for (int i=0; i < HTTP_BUFFER_MAX; i++) {
        if ((1 << i) & http_mask) printInterval(output, http_buffer_name[i], http_buffer[i].buf, http_buffer[i].length);
    }
}

// Legacy support function. Puts message fields into the buffers used by old Snort. This should go away.
void NHttpMsgHeader::oldClients() {
    ClearHttpBuffers();

    if (method.length > 0) SetHttpBuffer(HTTP_BUFFER_METHOD, method.start, (unsigned)method.length);
    if (uri.length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_URI, uri.start, (unsigned)uri.length);
    if (uri.length > 0) SetHttpBuffer(HTTP_BUFFER_URI, uri.start, (unsigned)uri.length);
    if (headers.length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_HEADER, headers.start, (unsigned)headers.length);
    if (headers.length > 0) SetHttpBuffer(HTTP_BUFFER_HEADER, headers.start, (unsigned)headers.length);
    if (statusCode.length > 0) SetHttpBuffer(HTTP_BUFFER_STAT_CODE, statusCode.start, (unsigned)statusCode.length);
    if (reasonPhrase.length > 0) SetHttpBuffer(HTTP_BUFFER_STAT_MSG, reasonPhrase.start, (unsigned)reasonPhrase.length);
 
    for (int k=0; (headerNameId[k] != HEAD__NOTCOMPUTE) && (k < MAXHEADERS); k++) {
        if (((headerNameId[k] == HEAD_COOKIE) && (sourceId == SRC_CLIENT)) || ((headerNameId[k] == HEAD_SET_COOKIE) && (sourceId == SRC_SERVER))) {
            if (headerValue[k].length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_COOKIE, headerValue[k].start, (unsigned)headerValue[k].length);
            break;
        }
    }

    if ((sourceId == SRC_CLIENT) && (headerValueNorm[HEAD_COOKIE].length > 0))
       SetHttpBuffer(HTTP_BUFFER_COOKIE, headerValueNorm[HEAD_COOKIE].start, (unsigned)headerValueNorm[HEAD_COOKIE].length);
    else if ((sourceId == SRC_SERVER) && (headerValueNorm[HEAD_SET_COOKIE].length > 0))
       SetHttpBuffer(HTTP_BUFFER_COOKIE, headerValueNorm[HEAD_SET_COOKIE].start, (unsigned)headerValueNorm[HEAD_SET_COOKIE].length);
}

