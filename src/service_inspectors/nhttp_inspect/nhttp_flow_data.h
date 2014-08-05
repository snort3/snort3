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

#ifndef NHTTP_FLOW_DATA_H
#define NHTTP_FLOW_DATA_H

#include "stream/stream_api.h"

class NHttpFlowData : public FlowData
{
public:
    NHttpFlowData();
    ~NHttpFlowData();
    static unsigned nhttp_flow_id;
    static void init() { nhttp_flow_id = FlowData::get_flow_id(); };

    friend class NHttpInspect;
    friend class NHttpMsgSection;
    friend class NHttpMsgHeader;
    friend class NHttpMsgStart;
    friend class NHttpMsgRequest;
    friend class NHttpMsgStatus;
    friend class NHttpMsgBody;
    friend class NHttpMsgChunkHead;
    friend class NHttpMsgChunkBody;
    friend class NHttpMsgTrailer;
    friend class NHttpStreamSplitter;
private:
    void halfReset(NHttpEnums::SourceId sourceId);

    // StreamSplitter => Inspector (facts about the most recent message section)
    // 0 element refers to client request, 1 element refers to server response
    NHttpEnums::SectionType sectionType[2] = { NHttpEnums::SEC__NOTCOMPUTE, NHttpEnums::SEC__NOTCOMPUTE };
    bool tcpClose[2] = { false, false };
    uint64_t infractions[2] = { 0, 0 };
    uint64_t eventsGenerated[2] = { 0, 0 };

    // Inspector => StreamSplitter (facts about the message section that is coming next)
    NHttpEnums::SectionType typeExpected[2] = { NHttpEnums::SEC_REQUEST, NHttpEnums::SEC_STATUS };
    int64_t octetsExpected[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };    // expected size of the upcoming body or chunk body section      

    // Inspector's internal data about the current message
    // Some items don't apply in both directions. Have two copies anyway just to simplify code and minimize hard-to-find bugs
    NHttpEnums::VersionId versionId[2] = { NHttpEnums::VERS__NOTPRESENT, NHttpEnums::VERS__NOTPRESENT };
    NHttpEnums::MethodId methodId[2] = { NHttpEnums::METH__NOTPRESENT, NHttpEnums::METH__NOTPRESENT };
    int32_t statusCodeNum[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };

    int64_t dataLength[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };        // length of the data from Content-Length field or chunk header.      
    int64_t bodySections[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };      // number of body sections seen so far including chunk headers
    int64_t bodyOctets[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };        // number of user data octets seen so far (either regular body or chunks)
    int64_t numChunks[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };         // number of chunks seen so far
    int64_t chunkSections[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };     // number of sections seen so far in the current chunk
    int64_t chunkOctets[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };       // number of user data octets seen so far in the current chunk including terminating CRLF

    // Stored message sections from this session
    // You must reset to nullptr after deleting a section
    // Never put one section in two places. latestOther is only for things not otherwise listed
    class NHttpMsgRequest* requestLine = nullptr;
    class NHttpMsgStatus* statusLine = nullptr;
    class NHttpMsgHeader* headers[2] = { nullptr, nullptr };
    class NHttpMsgSection* latestOther[2] = { nullptr, nullptr };
};

#endif










