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
//  @brief      NHttpMsgTrailer class analyzes HTTP chunked message trailers.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_trailer.h"

using namespace NHttpEnums;

NHttpMsgTrailer::NHttpMsgTrailer(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, SourceId sourceId_) :
   NHttpMsgHeadShared(buffer, bufSize, sessionData_, sourceId_) {
    delete sessionData->latestOther[sourceId];
    sessionData->latestOther[sourceId] = this;
}

void NHttpMsgTrailer::genEvents() {
    NHttpMsgHeadShared::genEvents();
}

void NHttpMsgTrailer::printSection(FILE *output) {
    NHttpMsgSection::printMessageTitle(output, "trailer");
    NHttpMsgHeadShared::printHeaders(output);
    NHttpMsgSection::printMessageWrapup(output);
}


void NHttpMsgTrailer::updateFlow() {
    if (tcpClose) {
        sessionData->typeExpected[sourceId] = SEC_CLOSED;
        sessionData->halfReset(sourceId);
    }
    else {
        sessionData->typeExpected[sourceId] = (sourceId == SRC_CLIENT) ? SEC_REQUEST : SEC_STATUS;
        sessionData->halfReset(sourceId);
    }
}























