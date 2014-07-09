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
//  @brief      NHttpMsgHeader class analyzes HTTP message headers
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_head.h"

using namespace NHttpEnums;

void NHttpMsgHeader::genEvents() {
    if (infractions != 0) SnortEventqAdd(NHTTP_GID, EVENT_ASCII); // I'm just an example event
}

void NHttpMsgHeader::printSection(FILE *output) const {
    NHttpMsgSection::printMessageTitle(output, "header");
    NHttpMsgHeadShared::printHeaders(output);
    NHttpMsgSection::printMessageWrapup(output);
}

void NHttpMsgHeader::updateFlow() {
    const uint64_t disasterMask = 0;

    ;
    headerNorms[HEAD_CONTENT_LENGTH]->normalize(HEAD_CONTENT_LENGTH, scratchPad, infractions, headerNameId, headerValue, MAXHEADERS, headerValueNorm[HEAD_CONTENT_LENGTH]);

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
        sessionData->typeExpected[sourceId] = (sourceId == SRC_CLIENT) ? SEC_REQUEST : SEC_STATUS;
        sessionData->halfReset(sourceId);
    }
    // If there is a Transfer-Encoding header, see if the last of the encoded values is "chunked".
    else if ( (headerNorms[HEAD_TRANSFER_ENCODING]->normalize(HEAD_TRANSFER_ENCODING, scratchPad, infractions,
                  headerNameId, headerValue, MAXHEADERS, headerValueNorm[HEAD_TRANSFER_ENCODING]) > 0) &&
            ((*(int64_t *)(headerValueNorm[HEAD_TRANSFER_ENCODING].start + (headerValueNorm[HEAD_TRANSFER_ENCODING].length - 8))) == TRANSCODE_CHUNKED) ) {
        // Chunked body
        sessionData->typeExpected[sourceId] = SEC_CHUNKHEAD;
        sessionData->bodySections[sourceId] = 0;
        sessionData->bodyOctets[sourceId] = 0;
        sessionData->numChunks[sourceId] = 0;
    }
    else if ((headerNorms[HEAD_CONTENT_LENGTH]->normalize(HEAD_CONTENT_LENGTH, scratchPad, infractions,
                 headerNameId, headerValue, MAXHEADERS, headerValueNorm[HEAD_CONTENT_LENGTH]) > 0) &&
            (*(int64_t*)headerValueNorm[HEAD_CONTENT_LENGTH].start > 0)) {
        // Regular body
        sessionData->typeExpected[sourceId] = SEC_BODY;
        sessionData->octetsExpected[sourceId] = *(int64_t*)headerValueNorm[HEAD_CONTENT_LENGTH].start;
        sessionData->dataLength[sourceId] = *(int64_t*)headerValueNorm[HEAD_CONTENT_LENGTH].start;
        sessionData->bodySections[sourceId] = 0;
        sessionData->bodyOctets[sourceId] = 0;
    }
    else {
        // No body
        sessionData->typeExpected[sourceId] = (sourceId == SRC_CLIENT) ? SEC_REQUEST : SEC_STATUS;
        sessionData->halfReset(sourceId);
    }
}

