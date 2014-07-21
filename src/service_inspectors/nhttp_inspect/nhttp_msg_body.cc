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
//  @brief      NHttpMsgBody class analyzes individual HTTP message bodies. Message chunks are handled in NHttpMsgChunk.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_body.h"

using namespace NHttpEnums;

NHttpMsgBody::NHttpMsgBody(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, SourceId sourceId_) :
   NHttpMsgSection(buffer, bufSize, sessionData_, sourceId_), dataLength(sessionData->dataLength[sourceId]),
   bodySections(sessionData->bodySections[sourceId]), bodyOctets(sessionData->bodyOctets[sourceId]) {}

void NHttpMsgBody::analyze() {
    bodySections++;
    bodyOctets += msgText.length;
    data.start = msgText.start;
    data.length = msgText.length;

    // The following statement tests for the case where streams underfulfilled flush due to a TCP connection close
    if ((msgText.length < 16384) && (bodyOctets < dataLength)) tcpClose = true;
    if (tcpClose && (bodyOctets < dataLength)) infractions |= INF_TRUNCATED;
}

void NHttpMsgBody::genEvents() {
// &&&    if (infractions != 0) createEvent(EVENT_ASCII); // I'm just an example event
}

void NHttpMsgBody::printSection(FILE *output) {
    NHttpMsgSection::printMessageTitle(output, "body");
    fprintf(output, "Expected data length %" PRIi64 ", sections seen %" PRIi64 ", octets seen %" PRIi64 "\n", dataLength, bodySections, bodyOctets);
    data.print(output, "Data");
    NHttpMsgSection::printMessageWrapup(output);
}

void NHttpMsgBody::updateFlow() {
    if (tcpClose) {
        sessionData->typeExpected[sourceId] = SEC_CLOSED;
        sessionData->halfReset(sourceId);
    }
    else if (bodyOctets < dataLength) {
        // More body coming
        sessionData->bodySections[sourceId] = bodySections;
        sessionData->bodyOctets[sourceId] = bodyOctets;
    }
    else {
        // End of message
        sessionData->typeExpected[sourceId] = (sourceId == SRC_CLIENT) ? SEC_REQUEST : SEC_STATUS;
        sessionData->halfReset(sourceId);
    }
}


// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgBody::legacyClients() {
    ClearHttpBuffers();
    if (data.length > 0) SetHttpBuffer(HTTP_BUFFER_CLIENT_BODY, data.start, (unsigned)data.length);
}
































