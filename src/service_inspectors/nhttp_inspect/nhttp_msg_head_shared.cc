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
//  @brief      NHttpMsgHeadShared virtual class rolls up all the common elements of header processing and trailer processing.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_normalizers.h"
#include "nhttp_msg_head_shared.h"

using namespace NHttpEnums;

// All the header processing that is done for every message (i.e. not just-in-time) is done here.
void NHttpMsgHeadShared::analyze() {
    parseWhole();
    parseHeaderBlock();
    parseHeaderLines();
    for (int j=0; j < numHeaders; j++) {
        deriveHeaderNameId(j);
        if (headerNameId[j] > 0) headerCount[headerNameId[j]]++;
    }
}

void NHttpMsgHeadShared::parseWhole() {
    // Normal case with header fields
    if (!tcpClose && (msgText.length >= 5)) {
        headers.start = msgText.start;
        headers.length = msgText.length - 4;
        assert(!memcmp(msgText.start+msgText.length-4, "\r\n\r\n", 4));
    }
    // Normal case no header fields
    else if (!tcpClose) {
        headers.length = STAT_NOTPRESENT;
        assert((msgText.length == 2) && !memcmp(msgText.start, "\r\n", 2));
    }
    // Normal case with header fields and TCP connection close
    else if ((msgText.length >= 5) && !memcmp(msgText.start+msgText.length-4, "\r\n\r\n", 4)) {
        headers.start = msgText.start;
        headers.length = msgText.length - 4;
    }
    // Normal case no header fields and TCP connection close
    else if ((msgText.length == 2) && !memcmp(msgText.start, "\r\n", 2)) {
        headers.length = STAT_NOTPRESENT;
    }
    // Abnormal cases truncated by TCP connection close
    else {
        infractions |= INF_TRUNCATED;
        // Lone <CR>
        if ((msgText.length == 1) && (msgText.start[0] == '\r')) {
            headers.length = STAT_NOTPRESENT;
        }
        // Truncation occurred somewhere in the header fields
        else {
            headers.start = msgText.start;
            headers.length = msgText.length;
            // When present, remove partial <CR><LF><CR><LF> sequence from the end
            if ((msgText.length >= 4) && !memcmp(msgText.start+msgText.length-3, "\r\n\r", 3)) headers.length -= 3;
            else if ((msgText.length >= 3) && !memcmp(msgText.start+msgText.length-2, "\r\n", 2)) headers.length -= 2;
            else if ((msgText.length >= 2) && (msgText.start[msgText.length-1] == '\r')) headers.length -= 1;
        }
    }
}

// Divide up the block of header fields into individual header field lines.
void NHttpMsgHeadShared::parseHeaderBlock() {
    if (headers.length < 0) {
        numHeaders = STAT_NOSOURCE;
        return;
    }

    int32_t bytesUsed = 0;
    numHeaders = 0;
    while (bytesUsed < headers.length) {
        headerLine[numHeaders].start = headers.start + bytesUsed;
        headerLine[numHeaders].length = findCrlf(headerLine[numHeaders].start, headers.length - bytesUsed, true);
        bytesUsed += headerLine[numHeaders++].length + 2;
        if (numHeaders >= MAXHEADERS) {
             break;
        }
    }
    if (bytesUsed < headers.length) {
        infractions |= INF_TOOMANYHEADERS;
    }
}

// Divide header field lines into field name and field value
void NHttpMsgHeadShared::parseHeaderLines() {
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

void NHttpMsgHeadShared::deriveHeaderNameId(int index) {
    // Normalize header field name to lower case for matching purposes
    uint8_t *lowerName;
    if ((lowerName = scratchPad.request(headerName[index].length)) == nullptr) {
        infractions |= INF_NOSCRATCH;
        headerNameId[index] = HEAD__INSUFMEMORY;
        return;
    }
    norm2Lower(headerName[index].start, headerName[index].length, lowerName, infractions, nullptr);
    headerNameId[index] = (HeaderId) strToCode(lowerName, headerName[index].length, headerList);
}

void NHttpMsgHeadShared::genEvents() {
    if (infractions & INF_TOOMANYHEADERS) createEvent(EVENT_MAX_HEADERS);
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgHeadShared::legacyClients() {
    ClearHttpBuffers();

    if (headers.length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_HEADER, headers.start, (unsigned)headers.length);
    if (headers.length > 0) SetHttpBuffer(HTTP_BUFFER_HEADER, headers.start, (unsigned)headers.length);
 
    for (int k=0; k < numHeaders; k++) {
        if (((headerNameId[k] == HEAD_COOKIE) && (sourceId == SRC_CLIENT)) || ((headerNameId[k] == HEAD_SET_COOKIE) && (sourceId == SRC_SERVER))) {
            if (headerValue[k].length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_COOKIE, headerValue[k].start, (unsigned)headerValue[k].length);
            break;
        }
    }

    if (sourceId == SRC_CLIENT) {
       if (headerNorms[HEAD_COOKIE]->normalize(HEAD_COOKIE, headerCount[HEAD_COOKIE], scratchPad, infractions,
          headerNameId, headerValue, numHeaders, headerValueNorm[HEAD_COOKIE]) > 0) {
           SetHttpBuffer(HTTP_BUFFER_COOKIE, headerValueNorm[HEAD_COOKIE].start, (unsigned)headerValueNorm[HEAD_COOKIE].length);
       }
    }
    else {
       if (headerNorms[HEAD_SET_COOKIE]->normalize(HEAD_SET_COOKIE, headerCount[HEAD_SET_COOKIE], scratchPad, infractions,
          headerNameId, headerValue, numHeaders, headerValueNorm[HEAD_SET_COOKIE]) > 0) {
           SetHttpBuffer(HTTP_BUFFER_COOKIE, headerValueNorm[HEAD_SET_COOKIE].start, (unsigned)headerValueNorm[HEAD_SET_COOKIE].length);
       }
    }
}

void NHttpMsgHeadShared::printHeaders(FILE *output) {
    char titleBuf[100];
    if (numHeaders != STAT_NOSOURCE) fprintf(output, "Number of headers: %d\n", numHeaders);
    for (int j=0; j < numHeaders; j++) {
        snprintf(titleBuf, sizeof(titleBuf), "Header ID %d", headerNameId[j]);
        headerValue[j].print(output, titleBuf);
    }
    for (int k=1; k <= numNorms; k++) {
        if (headerNorms[k]->normalize((HeaderId)k, headerCount[k], scratchPad, infractions, headerNameId, headerValue, numHeaders, headerValueNorm[k]) != STAT_NOSOURCE) {
            snprintf(titleBuf, sizeof(titleBuf), "Normalized header %d", k);
            headerValueNorm[k].print(output, titleBuf, true);
        }
    }
}





