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
//  @brief      NHttp Inspector class.
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdexcept>

#include "snort.h"
#include "stream/stream_api.h"
#include "nhttp_enum.h"
#include "nhttp_stream_splitter.h"
#include "nhttp_api.h"
#include "nhttp_inspect.h"

using namespace NHttpEnums;

THREAD_LOCAL NHttpMsgRequest* NHttpInspect::msgRequest;
THREAD_LOCAL NHttpMsgStatus* NHttpInspect::msgStatus;
THREAD_LOCAL NHttpMsgHeader* NHttpInspect::msgHead;
THREAD_LOCAL NHttpMsgBody* NHttpInspect::msgBody;
THREAD_LOCAL NHttpMsgChunkHead* NHttpInspect::msgChunkHead;
THREAD_LOCAL NHttpMsgChunkBody* NHttpInspect::msgChunkBody;
THREAD_LOCAL NHttpMsgTrailer* NHttpInspect::msgTrailer;

NHttpInspect::NHttpInspect(bool test_input, bool _test_output) : test_output(_test_output)
{
    NHttpTestInput::test_input = test_input;
    if (NHttpTestInput::test_input) {
        NHttpTestInput::testInput = new NHttpTestInput(testInputFile);
    }
}

NHttpInspect::~NHttpInspect ()
{
    if (NHttpTestInput::test_input) {
        delete NHttpTestInput::testInput;
        if (testOut) fclose(testOut);
    }
}

bool NHttpInspect::enabled ()
{
    return true;
}

bool NHttpInspect::configure (SnortConfig *)
{
    return true;
}

bool NHttpInspect::get_buf(unsigned id, Packet*, InspectionBuffer& b)
{
    const HttpBuffer* h = GetHttpBuffer((HTTP_BUFFER)id);

    if ( !h )
        return false;

    b.data = h->buf;
    b.len = h->length;
    return true;
}

int NHttpInspect::verify(SnortConfig*)
{
    return 0; // 0 = good, -1 = bad
}

void NHttpInspect::pinit()
{
}

void NHttpInspect::pterm()
{
}

void NHttpInspect::show(SnortConfig*)
{
    LogMessage("NHttpInspect\n");
}

void NHttpInspect::eval(Packet* p)
{
    // Only packets from the StreamSplitter can be processed
    if (!PacketHasPAFPayload(p)) return;

    process(p->data, p->dsize, p->flow);
}

void NHttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow)
{
    NHttpFlowData* sessionData = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    assert(sessionData);

    NHttpMsgSection *msgSect = nullptr;

    if (!NHttpTestInput::test_input) {
        switch (sessionData->sectionType) {
          case SEC_REQUEST: msgSect = msgRequest; break;
          case SEC_STATUS: msgSect = msgStatus; break;
          case SEC_HEADER: msgSect = msgHead; break;
          case SEC_BODY: msgSect = msgBody; break;
          case SEC_CHUNKHEAD: msgSect = msgChunkHead; break;
          case SEC_CHUNKBODY: msgSect = msgChunkBody; break;
          case SEC_TRAILER: msgSect = msgTrailer; break;
          case SEC_DISCARD: return;
          default: assert(0); return;
        }
        msgSect->loadSection(data, dsize, sessionData);
    }
    else {
        uint8_t *testBuffer;
        uint16_t testLength;
        if ((testLength = NHttpTestInput::testInput->toEval(&testBuffer, testNumber)) > 0) {
            switch (sessionData->sectionType) {
              case SEC_REQUEST: msgSect = msgRequest; break;
              case SEC_STATUS: msgSect = msgStatus; break;
              case SEC_HEADER: msgSect = msgHead; break;
              case SEC_BODY: msgSect = msgBody; break;
              case SEC_CHUNKHEAD: msgSect = msgChunkHead; break;
              case SEC_CHUNKBODY: msgSect = msgChunkBody; break;
              case SEC_TRAILER: msgSect = msgTrailer; break;
              case SEC_DISCARD: return;
              default: assert(0); return;
            }
            msgSect->loadSection(testBuffer, testLength, sessionData);
        }
        else {
            printf("Zero length test data.\n");
            return;
        }
    }
    msgSect->initSection();
    msgSect->analyze();
    msgSect->updateFlow();
    msgSect->genEvents();
    msgSect->legacyClients();

    if (test_output) {
        if (!NHttpTestInput::test_input) msgSect->printSection(stdout);
        else {
            if (testNumber != fileTestNumber) {
                if (testOut) fclose (testOut);
                fileTestNumber = testNumber;
                char fileName[100];
                snprintf(fileName, sizeof(fileName), "%s%" PRIi64 ".txt", testOutputPrefix, testNumber);
                if ((testOut = fopen(fileName, "w+")) == nullptr) throw std::runtime_error("Cannot open test output file");
            }
            msgSect->printSection(testOut);
        }
    }
}




