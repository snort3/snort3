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
//  @brief      NHttpMsgSharedHead virtual class rolls up all the common elements of header processing and trailer processing.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_head_shared.h"

using namespace NHttpEnums;

// Reinitialize everything derived in preparation for analyzing a new message
void NHttpMsgSharedHead::initSection() {
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
void NHttpMsgSharedHead::analyze() {
    parseWhole();
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

// Divide up the block of header fields into individual header field lines.
void NHttpMsgSharedHead::parseHeaderBlock() {
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
void NHttpMsgSharedHead::parseHeaderLines() {
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

void NHttpMsgSharedHead::deriveHeaderNameId(int index) {
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

void NHttpMsgSharedHead::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgSharedHead::legacyClients() const {
    ClearHttpBuffers();

    if (headers.length > 0) SetHttpBuffer(HTTP_BUFFER_RAW_HEADER, headers.start, (unsigned)headers.length);
    if (headers.length > 0) SetHttpBuffer(HTTP_BUFFER_HEADER, headers.start, (unsigned)headers.length);
 
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

void NHttpMsgSharedHead::printMessageHead(FILE *output) const {
    char titleBuf[100];
    if (numHeaders != STAT_NOTCOMPUTE) fprintf(output, "Number of headers: %d\n", numHeaders);
    for (int j=0; j < numHeaders && j < 200; j++) {
        snprintf(titleBuf, sizeof(titleBuf), "Header ID %d", headerNameId[j]);
        printInterval(output, titleBuf, headerValue[j].start, headerValue[j].length);
    }
    for (int k=1; k <= numNorms; k++) {
        if (headerValueNorm[k].length != STAT_NOTPRESENT) {
            snprintf(titleBuf, sizeof(titleBuf), "Normalized header %d", k);
            printInterval(output, titleBuf, headerValueNorm[k].start, headerValueNorm[k].length, true);
        }
    }
}










