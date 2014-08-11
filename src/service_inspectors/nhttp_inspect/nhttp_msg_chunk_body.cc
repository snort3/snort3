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
//  @brief      NHttpMsgChunkBody class analyzes data portion (not start line) of an HTTP chunk.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_chunk_body.h"

using namespace NHttpEnums;

NHttpMsgChunkBody::NHttpMsgChunkBody(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, SourceId sourceId_) :
   NHttpMsgBody(buffer, bufSize, sessionData_, sourceId_), numChunks(sessionData->numChunks[sourceId]),
   chunkSections(sessionData->chunkSections[sourceId]), chunkOctets(sessionData->chunkOctets[sourceId]) {}

void NHttpMsgChunkBody::analyze() {
    bodySections++;
    chunkOctets += msgText.length;
    bodyOctets += msgText.length;
    int termCrlfBytes = 0;
    if (chunkOctets > dataLength) {
        // Final <CR><LF> are not data and do not belong in octet total or data field
        termCrlfBytes = chunkOctets - dataLength;
        assert(termCrlfBytes <= 2);
        bodyOctets -= termCrlfBytes;
        // Check for correct CRLF termination. Beware the section might break just before chunk end.
        if ( ! ( ((termCrlfBytes == 2) && (msgText.length >= 2) && (msgText.start[msgText.length-2] == '\r') && (msgText.start[msgText.length-1] == '\n')) ||
                 ((termCrlfBytes == 2) && (msgText.length == 1) && (msgText.start[msgText.length-1] == '\n')) ||
                 ((termCrlfBytes == 1) && (msgText.start[msgText.length-1] == '\r')) ) ) {
            infractions |= INF_BROKENCHUNK;
        }
    }

    data.start = msgText.start;
    data.length = msgText.length - termCrlfBytes;

    chunkSections++;
    // The following statement tests for the case where streams underfulfilled flush due to a TCP connection close
    if ((msgText.length < 16384) && (bodyOctets + termCrlfBytes < dataLength + 2)) tcpClose = true;
    if (tcpClose) infractions |= INF_TRUNCATED;
}


void NHttpMsgChunkBody::genEvents() {}

void NHttpMsgChunkBody::printSection(FILE *output) {
    NHttpMsgSection::printMessageTitle(output, "chunk body");
    fprintf(output, "Expected chunk length %" PRIi64 ", cumulative sections %" PRIi64 ", cumulative octets %" PRIi64 "\n", dataLength, bodySections, bodyOctets);
    fprintf(output, "cumulative chunk sections %" PRIi64 ", cumulative chunk octets %" PRIi64 "\n", chunkSections, chunkOctets);
    data.print(output, "Data");
    NHttpMsgSection::printMessageWrapup(output);
}

void NHttpMsgChunkBody::updateFlow() {
    if (tcpClose) {
        sessionData->typeExpected[sourceId] = SEC_CLOSED;
        sessionData->halfReset(sourceId);
    }
    else if (chunkOctets < dataLength + 2) {
        sessionData->bodySections[sourceId] = bodySections;
        sessionData->bodyOctets[sourceId] = bodyOctets;
        sessionData->chunkSections[sourceId] = chunkSections;
        sessionData->chunkOctets[sourceId] = chunkOctets;
    }
    else {
        sessionData->typeExpected[sourceId] = SEC_CHUNKHEAD;
        sessionData->octetsExpected[sourceId] = STAT_NOTPRESENT;
        sessionData->dataLength[sourceId] = STAT_NOTPRESENT;
        sessionData->bodySections[sourceId] = bodySections;
        sessionData->bodyOctets[sourceId] = bodyOctets;
        sessionData->chunkSections[sourceId] = STAT_NOTPRESENT;
        sessionData->chunkOctets[sourceId] = STAT_NOTPRESENT;
    }
}


































