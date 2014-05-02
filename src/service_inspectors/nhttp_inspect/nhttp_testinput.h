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
//  @brief      Converts protocol constant string to enum
//

#ifndef NHTTP_TESTINPUT_H
#define NHTTP_TESTINPUT_H

// ntiGet() returns the same static buffer each time.
// Do not call it again before you are finished with the previous output.
class NHttpTestInput {
public:
    NHttpTestInput(const char *fileName);
    ~NHttpTestInput();
    int32_t ntiGet(uint8_t **buffer, NHttpFlowData* sessionData, int64_t &testNumber);
private:
    FILE *msgFile;
    uint8_t msgBuf[NHttpMsgHeader::MAXOCTETS];
};

#endif

