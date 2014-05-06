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
//  @brief      Interface to file test messages
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdexcept>
#include "snort.h"
#include "flow/flow.h"
#include "nhttp_enum.h"
#include "nhttp_scratchpad.h"
#include "nhttp_strtocode.h"
#include "nhttp_headnorm.h"
#include "nhttp_flowdata.h"
#include "nhttp_msgheader.h"
#include "nhttp_testinput.h"

NHttpTestInput::NHttpTestInput(const char *fileName) {
    if ((msgFile = fopen(fileName, "r")) == nullptr) throw std::runtime_error("Cannot open test input file");
}

NHttpTestInput::~NHttpTestInput() {
    fclose(msgFile);
}

// Read the next message section from the test data file.
// In the process we may need to skip comments, execute simple commands, and handle simple escape sequences.
// The best way to understand this function is to read the comments at the top of the file of test cases.
int32_t NHttpTestInput::ntiGet(uint8_t **buffer, NHttpFlowData* sessionData, int64_t &testNumber) {
    int32_t length = 0;
    *buffer = msgBuf;
    int newChar;
    typedef enum { WAITING, COMMENT, COMMAND, SECTION, ESCAPE0, ESCAPE1, ESCAPE2 } State;
    State state = WAITING;
    bool ending;
    char escapeNum[] = { 0, 0, '\0' };
    int commandLength = 0;
    const int MaxCommand = 100;
    char commandValue[MaxCommand];

    sessionData->tcpClose = false;
    sessionData->infractions = 0;

    while ((newChar = getc(msgFile)) != EOF) {
        switch (state) {
          case WAITING:
            if (newChar == '#') state = COMMENT;
            else if (newChar == '@') {
                state = COMMAND;
                commandLength = 0;
            }
            else if (newChar == '\\') {
                state = ESCAPE0;
                ending = false;
            }
            else if (newChar != '\n') {
                state = SECTION;
                ending = false;
                msgBuf[length++] = (uint8_t) newChar;
            }
            break;
          case COMMENT:
            if (newChar == '\n') state = WAITING;
            break;
          case COMMAND:
            if (newChar == '\n') {
                state = WAITING;
                if ((commandLength == strlen("request")) && !memcmp(commandValue, "request", strlen("request"))) sessionData->sourceId = NHttpEnums::SRC_CLIENT;
                else if ((commandLength == strlen("response")) && !memcmp(commandValue, "response", strlen("response"))) sessionData->sourceId = NHttpEnums::SRC_SERVER;
                else if ((commandLength == strlen("tcpclose")) && !memcmp(commandValue, "tcpclose", strlen("tcpclose"))) sessionData->tcpClose = true;
                else if ((commandLength == strlen("break")) && !memcmp(commandValue, "break", strlen("break"))) {
                    // &&& signifies start of new session so wipe "session data" when we define some. See flowdata.h.
                }
                else if (commandLength > 0) {
                    // Look for a test number
                    bool isNumber = true;
                    for (int k=0; isNumber && (k < commandLength); k++) {
                        isNumber = (commandValue[k] >= '0') && (commandValue[k] <= '9');
                    }
                    if (isNumber) {
                        testNumber = 0;
                        for (int j=0; j < commandLength; j++) {
                            testNumber = testNumber * 10 + (commandValue[j] - '0');
                        }
                    }
                }
            }
            else {
                if (commandLength < MaxCommand) commandValue[commandLength++] = newChar;
            }
            break;
          case SECTION:
            if (newChar == '\\') {
                state = ESCAPE0;
            }
            else if (newChar == '\n') {
                if (ending) return length;  // Found the blank line that ends the section.
                ending = true;
            }
            else {
                ending = false;
                msgBuf[length++] = (uint8_t) newChar;
            }
            break;
          case ESCAPE0:
            if (newChar == 'n')       { state = SECTION; ending = false; msgBuf[length++] = '\n'; }
            else if (newChar == 'r')  { state = SECTION; ending = false; msgBuf[length++] = '\r'; }
            else if (newChar == 't')  { state = SECTION; ending = false; msgBuf[length++] = '\t'; }
            else if (newChar == '#')  { state = SECTION; ending = false; msgBuf[length++] = '#';  }
            else if (newChar == '@')  { state = SECTION; ending = false; msgBuf[length++] = '@';  }
            else if (newChar == '\\') { state = SECTION; ending = false; msgBuf[length++] = '\\'; }
            else if ((newChar == 'x') || (newChar == 'X')) state = ESCAPE1;
            else                      { state = SECTION; ending = false; }
            break;
          case ESCAPE1:
            state = ESCAPE2;
            escapeNum[0] = newChar;
            break;
          case ESCAPE2:
            state = SECTION;
            ending = false;
            escapeNum[1] = newChar;
            if (((escapeNum[0] < '0') || (escapeNum[0] > '9')) && ((escapeNum[0] < 'A') || (escapeNum[0] > 'Z')) && ((escapeNum[0] < 'a') || (escapeNum[0] > 'z'))) break;
            if (((escapeNum[1] < '0') || (escapeNum[1] > '9')) && ((escapeNum[1] < 'A') || (escapeNum[1] > 'Z')) && ((escapeNum[1] < 'a') || (escapeNum[1] > 'z'))) break;
            msgBuf[length++] = strtoul(escapeNum, nullptr, 16);
            break;
        }
        // Return because the buffer is full. Not a feature just a safety precaution against bad input.
        if (length >= sizeof(msgBuf)) return length;
    }
    // End-of-file. Return everything we have so far.
    return length;
}


