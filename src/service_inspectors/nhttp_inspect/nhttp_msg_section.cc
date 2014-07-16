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
   length(bufSize), sessionData(sessionData_), sourceId(sourceId_), tcpClose(sessionData->tcpClose[sourceId]),
   scratchPad(2*length+500), infractions(sessionData->infractions[sourceId]), versionId(sessionData->versionId[sourceId]),
   methodId(sessionData->methodId[sourceId]), statusCodeNum(sessionData->statusCodeNum[sourceId])
{
    rawBuf = new uint8_t[length];
    memcpy(rawBuf, buffer, length);
    msgText = rawBuf;
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

void NHttpMsgSection::printInterval(FILE *output, const char* name, const uint8_t *text, int32_t length, bool intVals) {
    if ((length == STAT_NOTPRESENT) || (length == STAT_NOTCOMPUTE) || (length == STAT_NOSOURCE)) return;
    int outCount = fprintf(output, "%s, length = %d, ", name, length);
    if (length <= 0) {
        fprintf(output, "\n");
        return;
    }
    if (text == nullptr) {
        fprintf(output, "nullptr\n");
        return;
    }
    if (length > 1000) length = 1000;    // Limit the amount of data printed
    for (int k=0; k < length; k++) {
        if ((text[k] >= 0x20) && (text[k] <= 0x7E)) fprintf(output, "%c", (char)text[k]);
        else if (text[k] == 0xD) fprintf(output, "~");
        else if (text[k] == 0xA) fprintf(output, "^");
        else fprintf(output, "*");
        if ((k%120 == (119 - outCount)) && (k+1 < length)) fprintf(output, "\n");
    }

    if (intVals && (length%8 == 0)) {
        fprintf(output, "\nInteger values =");
        for (int j=0; j < length; j+=8) {
            fprintf(output, " %" PRIu64 , *((const uint64_t*)(text+j)));
        }
    }
    fprintf(output, "\n");
}

void NHttpMsgSection::printMessageTitle(FILE *output, const char *title) const {
    fprintf(output, "HTTP message %s:\n", title);
    printInterval(output, "Input", msgText, length);
}

void NHttpMsgSection::printMessageWrapup(FILE *output) const {
    fprintf(output, "Infractions: %" PRIx64 ", TCP Close: %s\n", infractions, tcpClose ? "True" : "False");
    fprintf(output, "Interface to old clients. http_mask = %x.\n", http_mask);
    for (int i=0; i < HTTP_BUFFER_MAX; i++) {
        if ((1 << i) & http_mask) printInterval(output, http_buffer_name[i], http_buffer[i].buf, http_buffer[i].length);
    }
    fprintf(output, "\n");
}

