/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
//  @brief      NHttpMsgSection class is virtual parent for classes that analyze individual HTTP message sections.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_section.h"

using namespace NHttpEnums;

NHttpMsgSection::NHttpMsgSection(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, SourceId sourceId_) :
   sessionData(sessionData_), sourceId(sourceId_), tcpClose(sessionData->tcpClose[sourceId]), scratchPad(2*bufSize+500),
   infractions(sessionData->infractions[sourceId]), eventsGenerated(sessionData->eventsGenerated[sourceId]),
   versionId(sessionData->versionId[sourceId]), methodId(sessionData->methodId[sourceId]), statusCodeNum(sessionData->statusCodeNum[sourceId])
{
    rawBuf = new uint8_t[bufSize];
    memcpy(rawBuf, buffer, bufSize);
    msgText.start = rawBuf;
    msgText.length = bufSize;
}

// Return the number of octets before the first CRLF. Return length if CRLF not present.
//
// wrappable: CRLF does not count in a header field when immediately followed by <SP> or <LF>. These whitespace characters
// at the beginning of the next line indicate that the previous header has wrapped and is continuing on the next line.
uint32_t NHttpMsgSection::findCrlf(const uint8_t* buffer, int32_t length, bool wrappable) {
    for (int32_t k=0; k < length-1; k++) {
        if ((buffer[k] == '\r') && (buffer[k+1] == '\n'))
            if (!wrappable || (k+2 >= length) || ((buffer[k+2] != ' ') && (buffer[k+2] != '\t'))) return k;
    }
    return length;
}

void NHttpMsgSection::printMessageTitle(FILE *output, const char *title) const {
    fprintf(output, "HTTP message %s:\n", title);
    msgText.print(output, "Input");
}

void NHttpMsgSection::printMessageWrapup(FILE *output) const {
    fprintf(output, "Infractions: %" PRIx64 ", Events: %" PRIx64 ", TCP Close: %s\n", infractions, eventsGenerated,
       tcpClose ? "True" : "False");
    fprintf(output, "Interface to old clients. http_mask = %x.\n", http_mask);
    for (int i=0; i < HTTP_BUFFER_MAX; i++) {
        if ((1 << i) & http_mask) Field(http_buffer[i].length, http_buffer[i].buf).print(output, http_buffer_name[i]);
    }
    fprintf(output, "\n");
}

void NHttpMsgSection::createEvent(EventSid sid) {
    const uint32_t NHTTP_GID = 119;
    SnortEventqAdd(NHTTP_GID, (uint32_t)sid);
    eventsGenerated |= (1 << (sid-1));
}

















