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
//  @brief      NHttpMsgSection class declaration
//

#ifndef NHTTP_MSG_SECTION_H
#define NHTTP_MSG_SECTION_H

#include "detection/detection_util.h"
#include "nhttp_scratch_pad.h"
#include "nhttp_flow_data.h"

//-------------------------------------------------------------------------
// NHttpMsgSection class
//-------------------------------------------------------------------------

class NHttpMsgSection {
public:
    virtual void loadSection(const uint8_t *buffer, const uint16_t bufsize, NHttpFlowData *sessionData_);
    virtual ~NHttpMsgSection() = default;
    virtual void initSection() = 0;
    virtual void analyze() = 0;                           // Minimum necessary processing for every message
    virtual void analyzeAll() {};                         // Force all just-in-time processing (testing method)
    virtual void printSection(FILE *output) const = 0;
    virtual void genEvents() = 0;
    virtual void updateFlow() = 0;
    virtual void legacyClients() = 0;

protected:
    // Convenience methods
    static uint32_t findCrlf(const uint8_t* buffer, int32_t length, bool wrappable);
    static void printInterval(FILE *output, const char* name, const uint8_t *text, int32_t length, bool intVals = false);
    void printMessageTitle(FILE *output, const char *title) const;
    void printMessageWrapup(FILE *output) const;

    // The current strategy is to copy the entire raw message section into this object. Here it is.
    int32_t length;               // Length of the original message section in octets
    uint8_t rawBuf[NHttpEnums::MAXOCTETS];    // The original HTTP message section octets
    // This pointer is the handle for working with the original message data. It makes it simple to later replace rawBuf with some other form of storage
    // such as the buffer in the packet structure or something dynamic. Const x 2 because this pointer should never change and people working with the
    // original message should not be changing it. Only loading a completely new message into rawBuf should do that.
    const uint8_t * const msgText = rawBuf;

    NHttpFlowData* sessionData;
    ScratchPad scratchPad {NHttpEnums::MAXOCTETS*2};

    // This is where all the derived values, extracted message parts, and normalized values are.
    // Note that these are all scalars, buffer pointers, and buffer sizes. The actual buffers are in message buffer (raw pieces) or the
    // scratchPad (normalized pieces).
    uint64_t infractions;
    bool tcpClose;
    NHttpEnums::SourceId sourceId;
    NHttpEnums::VersionId versionId;
    NHttpEnums::MethodId methodId;
    int32_t statusCodeNum;
};

#endif



















