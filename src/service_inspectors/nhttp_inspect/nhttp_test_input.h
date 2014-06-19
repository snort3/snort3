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
//  @brief      Read test file and present test input to PAF
//

#ifndef NHTTP_TEST_INPUT_H
#define NHTTP_TEST_INPUT_H

class NHttpTestInput {
public:
    NHttpTestInput(const char *fileName);
    ~NHttpTestInput();
    void toPaf(uint8_t*& data, uint32_t &length, NHttpEnums::SourceId &sourceId, bool &tcpClose, bool &needBreak);
    void pafFlush(uint32_t length);
    uint16_t toEval(uint8_t **buffer, int64_t &testNumber);

    // Hard for NHttpInspect and PAF to share these without making them "global". This is as good a place as any for them to live.
    static bool test_input;
    static NHttpTestInput *testInput;
private:
    FILE *testDataFile;
    uint8_t msgBuf[2 * NHttpEnums::MAXOCTETS];
    bool flushed = false;   // verifies alternation between PAF section flushing and eval() section processing
    bool justFlushed = true;   // toPaf() needs to do special post-flush processing before it resumes reading the file
    bool tcpAlreadyClosed = false;  // so we can keep presenting a TCP close to PAF until all the remaining octets are consumed and flushed
    uint32_t flushOffset = 0;  // last character in buffer that has been flushed by PAF and must go to eval().
    uint32_t previousOffset = 0;   // last character in the buffer shown to PAF but not flushed yet
    uint32_t endOffset = 0;   // last read character in the buffer
    bool bodyData = false;  // pending output of fill data
    uint32_t fillOctets = 0;    // remaining fill data
    int64_t testNumber = 0;   // for numbering test output files
    uint32_t mssLength = 1460;   // Maximum Segment Size. Needs to be enhanced to be set through a command.
    NHttpEnums::SourceId lastSourceId = NHttpEnums::SRC_CLIENT;   // current direction of traffic flow. Toggled by commands in file.
    uint8_t termBytes[2] = { 'x', 'y' };
};

#endif

