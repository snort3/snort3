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
//  @brief      NHttpMsgHeadShared class declaration
//

#ifndef NHTTP_MSG_HEAD_SHARED_H
#define NHTTP_MSG_HEAD_SHARED_H

#include "nhttp_str_to_code.h"
#include "nhttp_head_norm.h"
#include "nhttp_msg_section.h"
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpMsgHeadShared class
//-------------------------------------------------------------------------

class NHttpMsgHeadShared: public NHttpMsgSection {
public:
    void analyze();
    void genEvents();
    void legacyClients();

protected:
    NHttpMsgHeadShared(const uint8_t *buffer, const uint16_t bufSize, NHttpFlowData *sessionData_, NHttpEnums::SourceId sourceId_) :
       NHttpMsgSection(buffer, bufSize, sessionData_, sourceId_) {};

    // Header normalization strategies. There should be one of these for every different way we can process a header field value.
    static const HeaderNormalizer NORMALIZER_NIL;
    static const HeaderNormalizer NORMALIZER_BASIC;
    static const HeaderNormalizer NORMALIZER_CAT;
    static const HeaderNormalizer NORMALIZER_NOREPEAT;
    static const HeaderNormalizer NORMALIZER_DECIMAL;
    static const HeaderNormalizer NORMALIZER_TRANSCODE;

    // Master table of known header fields and their normalization strategies.
    static const HeaderNormalizer* const headerNorms[];
    static const int32_t numNorms;

    // Tables of header field names and header value names
    static const StrCode headerList[];
    static const StrCode transCodeList[];

    void parseWhole();
    void parseHeaderBlock();
    void parseHeaderLines();
    void deriveHeaderNameId(int index);

    void printHeaders(FILE *output);

    Field headers;

    // All of these are indexed by the relative position of the header field in the message
    static const int MAXHEADERS = 200;  // I'm an arbitrary number. Need to revisit.
    int32_t numHeaders = NHttpEnums::STAT_NOTCOMPUTE;
    Field headerLine[MAXHEADERS];
    Field headerName[MAXHEADERS];
    NHttpEnums::HeaderId headerNameId[MAXHEADERS];
    Field headerValue[MAXHEADERS];

    // Normalized values are indexed by HeaderId
    int headerCount[NHttpEnums::HEAD__MAXVALUE] = { };
    Field headerValueNorm[NHttpEnums::HEAD__MAXVALUE];
};

#endif



















