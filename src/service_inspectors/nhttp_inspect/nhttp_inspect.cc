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
#include "framework/inspector.h"
#include "flow/flow.h"
#include "nhttp_enum.h"
#include "nhttp_scratchpad.h"
#include "nhttp_strtocode.h"
#include "nhttp_headnorm.h"
#include "nhttp_flowdata.h"
#include "nhttp_msgheader.h"
#include "nhttp_testinput.h"
#include "nhttp_api.h"
#include "nhttp_inspect.h"

const char* NHttpInspect::testInputFile = "nhttptestmsgs.txt";
const char* NHttpInspect::testOutputPrefix = "nhttpresults/testcase";
THREAD_LOCAL NHttpMsgHeader* NHttpInspect::msgHead;

NHttpInspect::NHttpInspect(bool _test_mode) : test_mode(_test_mode)
{
    printf("NHttpInspect constructor()\n");
    if (test_mode) {
        testInput = new NHttpTestInput(testInputFile);
    }
}

NHttpInspect::~NHttpInspect ()
{
    printf("NHttpInspect destructor()\n");
    if (test_mode) {
        delete testInput;
        if (testOut) fclose(testOut);
    }
}

bool NHttpInspect::enabled ()
{
    printf("NHttpInspect enabled()\n");
    return true;
}

void NHttpInspect::configure (SnortConfig *sc, const char*, char *args)
{
    printf("NHttpInspect configure()\n");
}

int NHttpInspect::verify(SnortConfig* sc)
{
    printf("NHttpInspect verify()\n");
    return 0; // 0 = good, -1 = bad
}

void NHttpInspect::pinit()
{
    printf("NHttpInspect pinit()\n");
}

void NHttpInspect::pterm()
{
    printf("NHttpInspect pterm()\n");
}

void NHttpInspect::show(SnortConfig*)
{
    printf("NHttpInspect show()\n");
    LogMessage("NHttpInspect\n");
}

void NHttpInspect::eval (Packet* p)
{
    printf("NHttpInspect eval()\n");

    Flow *flow = p->flow;
    NHttpFlowData* sessionData = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    if (sessionData == nullptr) flow->set_application_data(sessionData = new NHttpFlowData);

    if (!test_mode) msgHead->loadMessage(p->data, p->dsize, sessionData);
    else {
        uint8_t *testBuffer;
        int32_t testLength;
        if ((testLength = testInput->ntiGet(&testBuffer, sessionData, testNumber)) > 0) {
            msgHead->loadMessage(testBuffer, testLength, sessionData);
        }
        else {
            printf("Out of test data.\n");
            return;
        }
    }

    msgHead->analyze();

    msgHead->genEvents();

    // Interface to the old Snort clients
    msgHead->oldClients();

    if (!test_mode) msgHead->printMessage(stdout);
    else {
        if (testNumber != fileTestNumber) {
            if (testOut) fclose (testOut);
            fileTestNumber = testNumber;
            char fileName[100];
            sprintf(fileName, "%s%d.txt", testOutputPrefix, testNumber);
            if ((testOut = fopen(fileName, "w+")) == nullptr) throw std::runtime_error("Cannot open test output file");
        }
        msgHead->printMessage(testOut);
    }
}






