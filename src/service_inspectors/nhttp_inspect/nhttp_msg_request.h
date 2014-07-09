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
//  @brief      NHttpMsgRequest class declaration
//

#ifndef NHTTP_MSG_REQUEST_H
#define NHTTP_MSG_REQUEST_H

#include "nhttp_str_to_code.h"
#include "nhttp_uri.h"
#include "nhttp_uri_norm.h"
#include "nhttp_msg_start.h"

//-------------------------------------------------------------------------
// NHttpMsgRequest class
//-------------------------------------------------------------------------

class NHttpMsgRequest: public NHttpMsgStart {
public:
    NHttpMsgRequest() {};
    ~NHttpMsgRequest() { delete uri; };
    void initSection();
    void printSection(FILE *output) const;
    void genEvents();
    void updateFlow();
    void legacyClients();

private:
    // Code conversion tables are for turning token strings into enums.
    static const StrCode methodList[];

    // "Parse" methods cut things into pieces. "Extract" methods find the named item. "Derive" methods convert things into a new format
    // such as an integer or enum token. "Normalize" methods convert things into a standard form without changing the underlying format.
    void parseStartLine();
    void deriveMethodId();

    // This is where all the derived values, extracted message parts, and normalized values are.
    // Note that these are all scalars, buffer pointers, and buffer sizes. The actual buffers are in the message buffer (raw pieces) or the
    // scratchPad (normalized pieces).
    field method;
    NHttpUri* uri = nullptr;
};

#endif



















