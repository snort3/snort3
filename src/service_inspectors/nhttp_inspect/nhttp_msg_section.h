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
    virtual ~NHttpMsgSection() {delete[] rawBuf;};
    virtual void analyze() = 0;                           // Minimum necessary processing for every message
    virtual void printSection(FILE *output) = 0;          // Test tool prints all derived message parts
    virtual void genEvents() = 0;                         // Converts collected information into required preprocessor events
    virtual void updateFlow() = 0;                        // Manages the splitter and communication between message sections
    virtual void legacyClients() = 0;                     // Populates the raw and normalized buffer interface used by old Snort

protected:
    NHttpMsgSection(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, NHttpEnums::SourceId sourceId_);

    // Convenience methods
    static uint32_t findCrlf(const uint8_t* buffer, int32_t length, bool wrappable);
    static void printInterval(FILE *output, const char* name, const uint8_t *text, int32_t length, bool intVals = false);
    void printMessageTitle(FILE *output, const char *title) const;
    void printMessageWrapup(FILE *output) const;

    // The current strategy is to copy the entire raw message section into this object. Here it is.
    int32_t length;
    uint8_t* rawBuf;
    // This pseudonym for rawBuf isolates details of how the raw message is stored from everything else.
    const uint8_t* msgText;

    NHttpFlowData* sessionData;
    NHttpEnums::SourceId sourceId;
    bool tcpClose;
    ScratchPad scratchPad;

    // This is where all the derived values, extracted message parts, and normalized values are.
    // These are all scalars, buffer pointers, and buffer sizes. The actual buffers are in message buffer (raw pieces) or the
    // scratchPad (normalized pieces).
    uint64_t infractions;
    NHttpEnums::VersionId versionId;
    NHttpEnums::MethodId methodId;
    int32_t statusCodeNum;
};

#endif



















