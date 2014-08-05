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
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpMsgRequest class
//-------------------------------------------------------------------------

class NHttpMsgRequest: public NHttpMsgStart {
public:
    NHttpMsgRequest(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, NHttpEnums::SourceId sourceId_);
    ~NHttpMsgRequest() { delete uri; };
    void printSection(FILE *output);
    void genEvents();
    void updateFlow();
    void legacyClients();
    const Field& getMethod() { return method; };
    const Field& getUri();
    const Field& getUriNormLegacy();

private:
    static const StrCode methodList[];

    void parseStartLine();
    void deriveMethodId();

    Field method;
    NHttpUri* uri = nullptr;
};

#endif



















