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
//  @brief      NHttpMsgChunkHead class analyzes header line for a chunk.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_chunk_head.h"

using namespace NHttpEnums;

// Convert the hexadecimal chunk length.
// RFC says that zero may be written with multiple digits "000000".
// Arbitrary limit of 15 hex digits not including leading zeros ensures in a simple way against 64-bit overflow and should be
// vastly bigger than any legitimate chunk.
void NHttpMsgChunkHead::deriveChunkLength() {
    if (chunkSize.length <= 0) {
        dataLength = STAT_NOSOURCE;
        infractions |= INF_BADCHUNKSIZE;
        return;
    }
    dataLength = 0;
    int nonLeadingZeros = 0;
    for (int k=0; k < chunkSize.length; k++) {
        if (nonLeadingZeros || (chunkSize.start[k] != '0')) nonLeadingZeros++;
        if (nonLeadingZeros > 15) {
            dataLength = STAT_PROBLEMATIC;
            infractions |= INF_BADCHUNKSIZE;
            return;
        }

        dataLength *= 16;
        if ((chunkSize.start[k] >= '0') && (chunkSize.start[k] <= '9')) dataLength += chunkSize.start[k] - '0';
        else if ((chunkSize.start[k] >= 'A') && (chunkSize.start[k] <= 'F')) dataLength += chunkSize.start[k] - 'A' + 10;
        else if ((chunkSize.start[k] >= 'a') && (chunkSize.start[k] <= 'f')) dataLength += chunkSize.start[k] - 'a' + 10;
        else {
            dataLength = STAT_PROBLEMATIC;
            infractions |= INF_BADCHUNKSIZE;
            return;
        }
    }
}

void NHttpMsgChunkHead::loadSection(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_) {
    NHttpMsgSection::loadSection(buffer, bufSize, sessionData_);

    bodySections = sessionData->bodySections[sourceId];
    numChunks = sessionData->numChunks[sourceId];
}

void NHttpMsgChunkHead::initSection() {
    startLine.length = STAT_NOTCOMPUTE;
    chunkSize.length = STAT_NOTCOMPUTE;
    chunkExtensions.length = STAT_NOTCOMPUTE;
}

void NHttpMsgChunkHead::analyze() {
    bodySections++;
    // First section in a new chunk is just the start line.
    numChunks++;
    startLine.start = msgText;
    if (!tcpClose) startLine.length = length - 2;
    else startLine.length = findCrlf(startLine.start, length, false);
    chunkSize.start = msgText;
    // Start line format is chunk size in hex followed by optional semicolon and extensions field
    for (chunkSize.length = 0; (chunkSize.length < startLine.length) && (startLine.start[chunkSize.length] != ';'); chunkSize.length++);
    if (chunkSize.length == startLine.length) {
        chunkExtensions.length = STAT_NOTPRESENT;
    }
    else if (chunkSize.length == startLine.length - 1) {
        chunkExtensions.length = STAT_EMPTYSTRING;
    }
    else {
        chunkExtensions.start = msgText + chunkSize.length + 1;
        chunkExtensions.length = startLine.length - chunkSize.length - 1;
    }
    deriveChunkLength();
    if (tcpClose) infractions |= INF_TRUNCATED;
}

void NHttpMsgChunkHead::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

void NHttpMsgChunkHead::printSection(FILE *output) const {
    NHttpMsgSection::printMessageTitle(output, "chunk header");
    fprintf(output, "Chunk size: %" PRIi64 "\n", dataLength);
    printInterval(output, "Chunk extensions", chunkExtensions.start, chunkExtensions.length);
    NHttpMsgSection::printMessageWrapup(output);
}

void NHttpMsgChunkHead::updateFlow() {
    if (tcpClose) {
        sessionData->typeExpected[sourceId] = SEC_CLOSED;
        sessionData->halfReset(sourceId);
    }
    else if (dataLength > 0) {
        sessionData->typeExpected[sourceId] = SEC_CHUNKBODY;
        sessionData->octetsExpected[sourceId] = dataLength+2;
        sessionData->bodySections[sourceId] = bodySections;
        sessionData->numChunks[sourceId] = numChunks;
        sessionData->dataLength[sourceId] = dataLength;
        sessionData->chunkSections[sourceId] = 0;
        sessionData->chunkOctets[sourceId] = 0;
    }
    else {
        // This was zero-length last chunk, trailer comes next
        sessionData->typeExpected[sourceId] = SEC_TRAILER;
        sessionData->halfReset(sourceId);
    }
}


// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgChunkHead::legacyClients() {
    ClearHttpBuffers();
    if (startLine.length > 0) SetHttpBuffer(HTTP_BUFFER_CLIENT_BODY, startLine.start, (unsigned)startLine.length);
}










