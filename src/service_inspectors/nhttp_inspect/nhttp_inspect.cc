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

bool NHttpInspect::get_buf(
    InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    switch ( ibt )
    {
    case InspectionBuffer::IBT_KEY:
        return get_buf(HTTP_BUFFER_URI, p, b);

    case InspectionBuffer::IBT_HEADER:
        return get_buf(HTTP_BUFFER_HEADER, p, b);

    case InspectionBuffer::IBT_BODY:
        return get_buf(HTTP_BUFFER_CLIENT_BODY, p, b);

    default:
        return false;
    }   
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

void NHttpInspect::eval(Packet*)
{
    printf("eval()\n"); fflush(nullptr); /* &&& */
    return;
}

void NHttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow, SourceId sourceId)
{
    NHttpFlowData* sessionData = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    assert(sessionData);

    NHttpMsgSection *msgSection = nullptr;

    if (!NHttpTestInput::test_input) {
        switch (sessionData->sectionType[sourceId]) {
          case SEC_REQUEST: msgSection = new NHttpMsgRequest(data, dsize, sessionData, sourceId); break;
          case SEC_STATUS: msgSection = new NHttpMsgStatus(data, dsize, sessionData, sourceId); break;
          case SEC_HEADER: msgSection = new NHttpMsgHeader(data, dsize, sessionData, sourceId); break;
          case SEC_BODY: msgSection = new NHttpMsgBody(data, dsize, sessionData, sourceId); break;
          case SEC_CHUNKHEAD: msgSection = new NHttpMsgChunkHead(data, dsize, sessionData, sourceId); break;
          case SEC_CHUNKBODY: msgSection = new NHttpMsgChunkBody(data, dsize, sessionData, sourceId); break;
          case SEC_TRAILER: msgSection = new NHttpMsgTrailer(data, dsize, sessionData, sourceId); break;
          case SEC_DISCARD: return;
          default: assert(0); return;
        }
    }
    else {
        uint8_t *testBuffer;
        uint16_t testLength;
        if ((testLength = NHttpTestInput::testInput->toEval(&testBuffer, testNumber, sourceId)) > 0) {
            switch (sessionData->sectionType[sourceId]) {
              case SEC_REQUEST: msgSection = new NHttpMsgRequest(testBuffer, testLength, sessionData, sourceId); break;
              case SEC_STATUS: msgSection = new NHttpMsgStatus(testBuffer, testLength, sessionData, sourceId); break;
              case SEC_HEADER: msgSection = new NHttpMsgHeader(testBuffer, testLength, sessionData, sourceId); break;
              case SEC_BODY: msgSection = new NHttpMsgBody(testBuffer, testLength, sessionData, sourceId); break;
              case SEC_CHUNKHEAD: msgSection = new NHttpMsgChunkHead(testBuffer, testLength, sessionData, sourceId); break;
              case SEC_CHUNKBODY: msgSection = new NHttpMsgChunkBody(testBuffer, testLength, sessionData, sourceId); break;
              case SEC_TRAILER: msgSection = new NHttpMsgTrailer(testBuffer, testLength, sessionData, sourceId); break;
              case SEC_DISCARD: return;
              default: assert(0); return;
            }
        }
        else {
            printf("Zero length test data.\n");
            return;
        }
    }
    msgSection->analyze();
    msgSection->updateFlow();
    msgSection->genEvents();
    msgSection->legacyClients();

    if (test_output) {
        if (!NHttpTestInput::test_input) msgSection->printSection(stdout);
        else {
            if (testNumber != fileTestNumber) {
                if (testOut) fclose (testOut);
                fileTestNumber = testNumber;
                char fileName[100];
                snprintf(fileName, sizeof(fileName), "%s%" PRIi64 ".txt", testOutputPrefix, testNumber);
                if ((testOut = fopen(fileName, "w+")) == nullptr) throw std::runtime_error("Cannot open test output file");
            }
            msgSection->printSection(testOut);
            printf("Finished processing section from test %" PRIi64 "\n", testNumber);
        }
    }
}




