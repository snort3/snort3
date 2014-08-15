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
    void half_reset(NHttpEnums::SourceId source_id);

    // StreamSplitter internal data
    int64_t octets_seen[2] = { 0, 0 };
    int num_crlf[2] = { 0, 0 };
    
    // StreamSplitter => Inspector (facts about the most recent message section)
    // 0 element refers to client request, 1 element refers to server response
    NHttpEnums::SectionType section_type[2] = { NHttpEnums::SEC__NOTCOMPUTE, NHttpEnums::SEC__NOTCOMPUTE };
    bool tcp_close[2] = { false, false };
    uint64_t infractions[2] = { 0, 0 };

    // Inspector => StreamSplitter (facts about the message section that is coming next)
    NHttpEnums::SectionType type_expected[2] = { NHttpEnums::SEC_REQUEST, NHttpEnums::SEC_STATUS };
    int64_t octets_expected[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT }; // expected size of the upcoming body or chunk body section

    // Inspector's internal data about the current message
    // Some items don't apply in both directions. Have two copies anyway just to simplify code and minimize
    // hard-to-find bugs
    NHttpEnums::VersionId version_id[2] = { NHttpEnums::VERS__NOTPRESENT, NHttpEnums::VERS__NOTPRESENT };
    NHttpEnums::MethodId method_id[2] = { NHttpEnums::METH__NOTPRESENT, NHttpEnums::METH__NOTPRESENT };
    int32_t status_code_num[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };

    int64_t data_length[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };     // length of the data from Content-Length field or chunk header.      
    int64_t body_sections[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };   // number of body sections seen so far including chunk headers
    int64_t body_octets[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };     // number of user data octets seen so far (either regular body or chunks)
    int64_t num_chunks[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };      // number of chunks seen so far
    int64_t chunk_sections[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };  // number of sections seen so far in the current chunk
    int64_t chunk_octets[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };    // number of user data octets seen so far in the current chunk including terminating CRLF

    // Stored message sections from this session
    // You must reset to nullptr after deleting a section
    // Never put one section in two places. latestOther is only for things not otherwise listed
    class NHttpMsgRequest* request_line = nullptr;
    class NHttpMsgStatus* status_line = nullptr;
    class NHttpMsgHeader* headers[2] = { nullptr, nullptr };
    class NHttpMsgSection* latest_other[2] = { nullptr, nullptr };
};

#endif










