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
//  @brief      NHttpMsgHeader class declaration
//

#ifndef NHTTP_MSGHEADER_H
#define NHTTP_MSGHEADER_H


//-------------------------------------------------------------------------
// NHttpMsgHeader class
//-------------------------------------------------------------------------

class NHttpMsgHeader {
public:
    NHttpMsgHeader() {};
    void loadMessage(const uint8_t *buffer, const uint16_t bufsize, NHttpFlowData *sessionData_);
    void analyze();
    void printMessage(FILE *output);
    void genEvents();
    void oldClients();  // I'm a legacy support method and should go away eventually
    static const uint32_t MAXOCTETS = 65535;

private:
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
    static const StrCode methodList[];
    static const StrCode headerList[];
    static const StrCode transCodeList[];

    // "Parse" methods cut things into pieces. "Derive" methods convert things into a new format such as an integer or enum token. "Normalize" methods convert
    // things into a standard form without changing the underlying format.
    void parseWhole();
    void deriveSourceId();
    void parseRequestLine();
    void parseStatusLine();
    void parseHeaderBlock();
    void parseHeaderLines();
    void deriveHeaderNameId(int index);
    void deriveStatusCodeNum();
    void deriveVersionId();
    void deriveMethodId();

    // Convenience methods
    uint32_t findCrlf(const uint8_t* buffer, uint32_t length, bool wrappable);
    void printInterval(FILE *output, const char* name, const uint8_t *text, int32_t length, bool intVals = false);

    // The current strategy is to copy the entire raw message headers into this object. Here it is.
    uint32_t length;              // Length of the original message headers in octets
    uint8_t rawBuf[MAXOCTETS];    // The original HTTP message header octets
    // This pointer is the handle for working with the original message data. It makes it simple to later replace rawBuf with some other form of storage
    // such as the buffer in the packet structure or something dynamic. Const x 2 because this pointer should never change and people working with the
    // original message should not be changing it. Only loading a completely new message into rawBuf should do that.
    const uint8_t * const msgText = rawBuf;

    // Working space and storage for all the derived fields. See scratchPad.h for usage instructions.
    // Allocation size may be complete overkill. Need to revisit this.
    uint32_t derivedBuf[MAXOCTETS/4];
    NHttpFlowData* sessionData;
    ScratchPad scratchPad {derivedBuf, MAXOCTETS/4};

    // This is where all the derived values, extracted message parts, and normalized values are.
    // Note that this is all scalars, buffer pointers, and buffer sizes. The actual buffers are in the original message buffer (raw pieces) or the
    // scratchPad (normalized pieces).
    uint64_t infractions;
    bool tcpClose;
    field startLine;
    NHttpEnums::SourceId sourceId;
    field version;
    NHttpEnums::VersionId versionId;
    field method;
    NHttpEnums::MethodId methodId;
    field uri;
    field statusCode;
    int32_t statusCodeNum;
    field reasonPhrase;
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



















