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
//  @brief      HTTP Stream Splitter Class
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_test_input.h"
#include "nhttp_stream_splitter.h"

using namespace NHttpEnums;

// Convenience function. All the housekeeping that must be done before we can return PAF_FLUSH to stream.
void NHttpStreamSplitter::prepareFlush(NHttpFlowData* sessionData, uint32_t* flushOffset, SourceId sourceId, SectionType sectionType, bool tcpClose,
      uint64_t infractions, uint32_t numOctets) {
    sessionData->sectionType[sourceId] = sectionType;
    sessionData->tcpClose[sourceId] = tcpClose;
    sessionData->infractions[sourceId] = infractions;
    sessionData->eventsGenerated[sourceId] = eventsGenerated;
    if (tcpClose) sessionData->typeExpected[sourceId] = SEC_CLOSED;
    if (!NHttpTestInput::test_input) *flushOffset = numOctets;
    else NHttpTestInput::testInput->pafFlush(numOctets);
    octetsSeen = 0;
    numCrlf = 0;
}

void NHttpStreamSplitter::createEvent(EventSid sid) {
    SnortEventqAdd(NHTTP_GID, (uint32_t)sid);
    eventsGenerated |= 1 << (sid-1);
}

PAF_Status NHttpStreamSplitter::scan (Flow* flow, const uint8_t* data, uint32_t length, uint32_t flags, uint32_t* flushOffset) {
    // When the system begins providing TCP connection close information this won't always be false. &&&
    bool tcpClose = false;

    // This is the session state information we share with HTTP Inspect and store with stream. A session is defined by a TCP connection.
    // Since PAF is the first to see a new TCP connection the new flow data object is created here.
    NHttpFlowData* sessionData = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    if (sessionData == nullptr) flow->set_application_data(sessionData = new NHttpFlowData);
    assert(sessionData != nullptr);

    SourceId sourceId = (flags & PKT_FROM_CLIENT) ? SRC_CLIENT : SRC_SERVER;

    if (NHttpTestInput::test_input) {
        *flushOffset = length;
        bool needBreak;
        NHttpTestInput::testInput->toPaf((uint8_t*&)data, length, sourceId, tcpClose, needBreak);
        if (length == 0) return PAF_FLUSH;
        if (needBreak) flow->set_application_data(sessionData = new NHttpFlowData);
    }

    switch (SectionType type = sessionData->typeExpected[sourceId]) {
      case SEC_REQUEST:
      case SEC_STATUS:
      case SEC_HEADER:
      case SEC_CHUNKHEAD:
      case SEC_TRAILER:
        pafMax = 63780;
        for (uint32_t k = 0; k < length; k++) {
            octetsSeen++;
            // Count the alternating <CR> and <LF> characters we have seen in a row
            if (((data[k] == '\r') && (numCrlf%2 == 0)) || ((data[k] == '\n') && (numCrlf%2 == 1))) numCrlf++;
            else numCrlf = 0;

            // Check start line for leading CRLF because some 1.0 implementations put extra blank lines between messages. We tolerate this by quietly ignoring them.
            // Header/trailer may also have leading CRLF. That is completely normal and means there are no header/trailer lines.
            if ((numCrlf == 2) && (octetsSeen == 2) && (type != SEC_CHUNKHEAD)) {
                prepareFlush(sessionData, flushOffset, sourceId, ((type == SEC_REQUEST) || (type == SEC_STATUS)) ? SEC_DISCARD : type, tcpClose && (k == length-1), 0, k+1);
                return PAF_FLUSH;
            }
            // The start line and chunk header section always end with the first <CRLF>
            else if ((numCrlf == 2) && ((type == SEC_REQUEST) || (type == SEC_STATUS) || (type == SEC_CHUNKHEAD))) {
                prepareFlush(sessionData, flushOffset, sourceId, type, tcpClose && (k == length-1), 0, k+1);
                return PAF_FLUSH;
            }
            // The header and trailer sections always end with the first double <CRLF>
            else if (numCrlf == 4) {
                prepareFlush(sessionData, flushOffset, sourceId, type, tcpClose && (k == length-1), 0, k+1);
                return PAF_FLUSH;
            }
            // We must do this to protect ourself from buffer overrun.
            else if (octetsSeen >= 63780) {
                prepareFlush(sessionData, flushOffset, sourceId, type, tcpClose && (k == length-1), INF_HEADTOOLONG, k+1);
                return PAF_FLUSH;
            }
        }
        // Incomplete headers wait patiently for more data
        if (!tcpClose) return PAF_SEARCH;
        // Discard the oddball case where the new "message" starts with <CR><close>
        else if ((octetsSeen == 1) && (numCrlf == 1)) prepareFlush(sessionData, flushOffset, sourceId, SEC_DISCARD, true, 0, length);
        // TCP connection close, flush the partial header
        else prepareFlush(sessionData, flushOffset, sourceId, type, true, INF_TRUNCATED, length);
        return PAF_FLUSH;
      case SEC_BODY:
      case SEC_CHUNKBODY:
        pafMax = 16384;
        prepareFlush(sessionData, flushOffset, sourceId, type, tcpClose && (sessionData->octetsExpected[sourceId] >= length), 0, sessionData->octetsExpected[sourceId]);
        return PAF_FLUSH;
      case SEC_ABORT:
        return PAF_ABORT;
      default:
        assert(0);
        return PAF_ABORT;
    }
}


































