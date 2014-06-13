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
//  @brief      Interface to file of test messages
//


#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdexcept>
#include <stdint.h>

#include "nhttp_enum.h"
#include "nhttp_test_input.h"

using namespace NHttpEnums;

bool NHttpTestInput::test_mode = false;
NHttpTestInput *NHttpTestInput::testInput = nullptr;

NHttpTestInput::NHttpTestInput(const char *fileName) {
    if ((testDataFile = fopen(fileName, "r")) == nullptr) throw std::runtime_error("Cannot open test input file");
}

NHttpTestInput::~NHttpTestInput() {
    fclose(testDataFile);
}

// Read from the test data file and present to PAF.
// In the process we may need to skip comments, execute simple commands, and handle escape sequences.
// The best way to understand this function is to read the comments at the top of the file of test cases.
void NHttpTestInput::toPaf(uint8_t*& data, uint32_t &length, SourceId &sourceId, bool &tcpClose, bool &needBreak) {
    // No new data presented to PAF while the last section is still being flushed.
    if (flushed) {
        length = 0;
        return;
    }

    sourceId = lastSourceId;
    tcpClose = false;
    needBreak = false;

    if (justFlushed) {
        // PAF just flushed. There may or may not be leftover data in our buffer.
        justFlushed = false;
        data = msgBuf;
        length = endOffset - flushOffset;  // this is the leftover data
        previousOffset = 0;
        endOffset = length;
        if (length > 0) {
            // Must present unflushed leftovers to PAF again.
            // If we don't take this opportunity to left justify our data in the buffer we may "walk" to the right until we run out of buffer space
            memmove(msgBuf, msgBuf+flushOffset, length);
            tcpClose = tcpAlreadyClosed;
            return;
        }
        // If we reach here then PAF has already flushed all the data we have read so far.
        tcpAlreadyClosed = false;
    }
    else {
        // The data we gave PAF last time was not flushed
        length = 0;
        previousOffset = endOffset;
        data = msgBuf + previousOffset;
    }

    // Now we need to move forward by reading more data from the file
    int newChar;
    typedef enum { WAITING, COMMENT, COMMAND, SECTION, ESCAPE, HEXVAL, FILLNUM, BRIDGE } State;
    State state = WAITING;
    bool ending;
    int commandLength;
    const int MaxCommand = 100;
    char commandValue[MaxCommand];
    uint8_t hexVal;
    int numDigits;
    uint32_t fillLength;

    while ((newChar = getc(testDataFile)) != EOF) {
        switch (state) {
          case WAITING:
            if (newChar == '#') state = COMMENT;
            else if (newChar == '@') {
                state = COMMAND;
                commandLength = 0;
            }
            else if (newChar == '\\') {
                state = ESCAPE;
                ending = false;
            }
            else if (newChar != '\n') {
                state = SECTION;
                ending = false;
                data[length++] = (uint8_t) newChar;
            }
            break;
          case COMMENT:
            if (newChar == '\n') state = WAITING;
            break;
          case COMMAND:
            if (newChar == '\n') {
                state = WAITING;
                if ((commandLength == strlen("request")) && !memcmp(commandValue, "request", strlen("request"))) sourceId = lastSourceId = SRC_CLIENT;
                else if ((commandLength == strlen("response")) && !memcmp(commandValue, "response", strlen("response"))) sourceId = lastSourceId = SRC_SERVER;
                else if ((commandLength == strlen("break")) && !memcmp(commandValue, "break", strlen("break"))) needBreak = true;
                else if ((commandLength == strlen("bodyend")) && !memcmp(commandValue, "bodyend", strlen("bodyend"))) {
                    termBytes[0] = 'x';
                    termBytes[1] = 'y';
                }
                else if ((commandLength == strlen("chunkend")) && !memcmp(commandValue, "chunkend", strlen("chunkend"))) {
                    termBytes[0] = '\r';
                    termBytes[1] = '\n';
                }
                else if (commandLength > 0) {
                    // Look for a test number
                    bool isNumber = true;
                    for (int k=0; (k < commandLength) && isNumber; k++) {
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
                else assert(0);
            }
            break;
          case SECTION:
            if (newChar == '\\') {
                state = ESCAPE;
                ending = false;
            }
            else if (newChar == '\n') {
                if (ending) {
                    // Found the blank line that ends the section.
                    endOffset = previousOffset + length;
                    return;
                }
                ending = true;
            }
            else {
                ending = false;
                data[length++] = (uint8_t) newChar;
            }
            break;
          case ESCAPE:
            switch (newChar) {
              case 'n':  state = SECTION; data[length++] = '\n'; break;
              case 'r':  state = SECTION; data[length++] = '\r'; break;
              case 't':  state = SECTION; data[length++] = '\t'; break;
              case 'B':  state = BRIDGE; break;
              case 'C':  endOffset = previousOffset + length; return;
              case 'T':  tcpClose = tcpAlreadyClosed = true; endOffset = previousOffset + length; return;
              case '#':  state = SECTION; data[length++] = '#';  break;
              case '@':  state = SECTION; data[length++] = '@';  break;
              case '\\': state = SECTION; data[length++] = '\\'; break;
              case 'x':
              case 'X':  state = HEXVAL; hexVal = 0; numDigits = 0; break;
              case '/':  state = FILLNUM; fillLength = 0; break;
              default:   assert(0); state = SECTION; break;
            }
            break;
          case BRIDGE:
            if (newChar != '\n') {
                state = SECTION;
                data[length++] = (uint8_t) newChar;
            }
            break;
          case HEXVAL:
            if ((newChar >= '0') && (newChar <= '9')) hexVal = hexVal * 16 + (newChar - '0');
            else if ((newChar >= 'a') && (newChar <= 'f')) hexVal = hexVal * 16 + 10 + (newChar - 'a');
            else if ((newChar >= 'A') && (newChar <= 'F')) hexVal = hexVal * 16 + 10 + (newChar - 'A');
            else assert(0);
            if (++numDigits == 2) {
                data[length++] = hexVal;
                state = SECTION;
            }
            break;
          case FILLNUM:
            if (newChar != '/') {
                assert((newChar >= '0') && (newChar <= '9'));
                fillLength = fillLength * 10 + (newChar - '0');
                assert(fillLength <= sizeof(msgBuf));  
                break;
            }
            else {
                bodyData = true;
                // Add the specified number of fill characters to the buffer and cut.
                // Simulates body data at the end of a header segment or the first segment containing body data
                // Don't allow a buffer overrun.
                if (previousOffset + length + fillLength > sizeof(msgBuf)) assert(0);
                for (uint32_t k=0; k < fillLength; k++) {
                    data[length++] = 'x';
                }
                endOffset = previousOffset + length;
                return;
            }
        }
        // If we have reached the configured maximum segment size automatically cut the data.
        if (length >= mssLength) {
            endOffset = previousOffset + length;
            return;
        }
        // Don't allow a buffer overrun.
        if (previousOffset + length >= sizeof(msgBuf)) assert(0);
    }
    // End-of-file. Return everything we have so far.
    endOffset = previousOffset + length;
    return;
}

void NHttpTestInput::pafFlush(uint32_t length) {
    assert(!flushed);
    flushed = true;
    if (bodyData && (previousOffset + length >= endOffset)) {
        fillOctets = length;
        bodyData = false;
        previousOffset = 0;
        endOffset = 0;
        flushOffset = 0;
    }
    else {
        flushOffset = previousOffset + length;
    }
}


uint16_t NHttpTestInput::toEval(uint8_t **buffer, int64_t &testNumber_) {
    if (!flushed) return 0;
    testNumber_ = testNumber;
    *buffer = msgBuf;
    if (fillOctets > 0) {
        uint32_t fillOut = (fillOctets <= 16384) ? fillOctets : 16384;
        for (uint32_t k = 0; k < fillOut; k++) {
            msgBuf[k] = 'A' + k % 26;
        }
        fillOctets -= fillOut;
        if (fillOctets == 0) {
            if (fillOut > 1) msgBuf[fillOut-2] = termBytes[0];
            msgBuf[fillOut-1] = termBytes[1];
            flushed = false;
            justFlushed = true;
        }
        else if (fillOctets == 1) {
            msgBuf[fillOut-1] = termBytes[0];
        }
        return (uint16_t)fillOut;
    }
    flushed = false;
    justFlushed = true;
    return (uint16_t)flushOffset;
}














