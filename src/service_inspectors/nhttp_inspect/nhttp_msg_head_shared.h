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
//  @brief      NHttpMsgSharedHead class declaration
//

#ifndef NHTTP_MSG_HEAD_SHARED_H
#define NHTTP_MSG_HEAD_SHARED_H

#include "nhttp_str_to_code.h"
#include "nhttp_head_norm.h"
#include "nhttp_msg_section.h"

//-------------------------------------------------------------------------
// NHttpMsgSharedHead class
//-------------------------------------------------------------------------

class NHttpMsgSharedHead: public NHttpMsgSection {
public:
    void initSection();
    void analyze();
    void genEvents();
    void legacyClients() const;

protected:
    // Header normalization. There should be one of these for every different way we can process a header field value.
    static const HeaderNormalizer NORMALIZER_NIL;
    static const HeaderNormalizer NORMALIZER_BASIC;
    static const HeaderNormalizer NORMALIZER_CAT;
    static const HeaderNormalizer NORMALIZER_NOREPEAT;
    static const HeaderNormalizer NORMALIZER_DECIMAL;
    static const HeaderNormalizer NORMALIZER_TRANSCODE;

    // Master table of known header fields and their normalization strategies.
    static const HeaderNormalizer* const headerNorms[];
    static const int32_t numNorms;

    // Code conversion tables are for turning token strings into enums.
    static const StrCode headerList[];
    static const StrCode transCodeList[];

    // "Parse" methods cut things into pieces. "Derive" methods convert things into a new format such as an integer or enum token. "Normalize" methods convert
    // things into a standard form without changing the underlying format.
    virtual void parseWhole() = 0;
    void parseHeaderBlock();
    void parseHeaderLines();
    void deriveHeaderNameId(int index);

    void printMessageHead(FILE *output) const;

    // This is where all the derived values, extracted message parts, and normalized values are.
    // Note that this is all scalars, buffer pointers, and buffer sizes. The actual buffers are in the message buffer (raw pieces) or the
    // scratchPad (normalized pieces).
    field headers;
    static const int MAXHEADERS = 200;  // I'm an arbitrary number. Need to revisit.
    int32_t numHeaders;
    field headerLine[MAXHEADERS];
    field headerName[MAXHEADERS];
    NHttpEnums::HeaderId headerNameId[MAXHEADERS];
    field headerValue[MAXHEADERS];
    field headerValueNorm[NHttpEnums::HEAD__MAXVALUE];
};

#endif



















