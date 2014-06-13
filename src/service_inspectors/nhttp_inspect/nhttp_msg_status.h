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
//  @brief      NHttpMsgStatus class declaration
//

#ifndef NHTTP_MSG_STATUS_H
#define NHTTP_MSG_STATUS_H

#include "nhttp_msg_start.h"

//-------------------------------------------------------------------------
// NHttpMsgStatus class
//-------------------------------------------------------------------------

class NHttpMsgStatus: public NHttpMsgStart {
public:
    NHttpMsgStatus() {};
    void initSection();
    void analyze();
    void printSection(FILE *output) const;
    void genEvents();
    void updateFlow() const;
    void legacyClients() const;

private:
    // "Parse" methods cut things into pieces. "Derive" methods convert things into a new format such as an integer or enum token. "Normalize" methods convert
    // things into a standard form without changing the underlying format.
    void parseStartLine();
    void deriveStatusCodeNum();

    // This is where all the derived values, extracted message parts, and normalized values are.
    // Note that this is all scalars, buffer pointers, and buffer sizes. The actual buffers are in the message buffer (raw pieces) or the
    // scratchPad (normalized pieces).
    field statusCode;
    field reasonPhrase;
};

#endif










