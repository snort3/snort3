/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// nhttp_flow_data.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_FLOW_DATA_H
#define NHTTP_FLOW_DATA_H

#include <stdio.h>
#include "stream/stream_api.h"
#include "nhttp_splitter.h"

class NHttpTransaction;

class NHttpFlowData : public FlowData
{
public:
    NHttpFlowData();
    ~NHttpFlowData();
    void show(FILE* out_file) const;
    static unsigned nhttp_flow_id;
    static void init() { nhttp_flow_id = FlowData::get_flow_id(); };

    friend class NHttpInspect;
    friend class NHttpMsgSection;
    friend class NHttpMsgHeader;
    friend class NHttpMsgStart;
    friend class NHttpMsgRequest;
    friend class NHttpMsgStatus;
    friend class NHttpMsgBody;
    friend class NHttpMsgChunk;
    friend class NHttpMsgTrailer;
    friend class NHttpStreamSplitter;
    friend class NHttpTransaction;
    friend class NHttpTestInput;
private:
    void half_reset(NHttpEnums::SourceId source_id);

    // StreamSplitter internal data
    NHttpStartSplitter start_splitter[2];
    NHttpHeaderSplitter header_splitter[2];
    NHttpChunkSplitter chunk_splitter[2];
    NHttpTrailerSplitter trailer_splitter[2];
    uint32_t unused_octets_visible[2] = { 0, 0 };
    uint32_t header_octets_visible[2] = { 0, 0 };
    uint8_t *section_buffer[2] = { nullptr, nullptr };
    int32_t section_buffer_length[2] = { 0, 0 };
    uint8_t *chunk_buffer[2] = { nullptr, nullptr };
    int32_t chunk_buffer_length[2] = { 0, 0 };
    
    // StreamSplitter => Inspector (facts about the most recent message section)
    // 0 element refers to client request, 1 element refers to server response
    NHttpEnums::SectionType section_type[2] = { NHttpEnums::SEC__NOTCOMPUTE, NHttpEnums::SEC__NOTCOMPUTE };
    uint32_t num_excess[2] = { 0, 0 };
    bool tcp_close[2] = { false, false };
    uint64_t infractions[2] = { 0, 0 };

    // Inspector => StreamSplitter (facts about the message section that is coming next)
    NHttpEnums::SectionType type_expected[2] = { NHttpEnums::SEC_REQUEST, NHttpEnums::SEC_STATUS };
    int64_t data_length[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };   // length of the data from Content-Length field      

    // Inspector's internal data about the current message
    NHttpEnums::VersionId version_id[2] = { NHttpEnums::VERS__NOTPRESENT, NHttpEnums::VERS__NOTPRESENT };
    NHttpEnums::MethodId method_id = NHttpEnums::METH__NOTPRESENT;
    int32_t status_code_num = NHttpEnums::STAT_NOTPRESENT;

    int64_t body_octets[2] = { NHttpEnums::STAT_NOTPRESENT, NHttpEnums::STAT_NOTPRESENT };   // number of user data octets seen so far (regular body or chunks)

    // Transaction management including pipelining
    NHttpTransaction* transaction[2] = { nullptr, nullptr };
    static const int MAX_PIPELINE = 100;  // requests seen - responses seen <= MAX_PIPELINE
    NHttpTransaction* pipeline[MAX_PIPELINE];
    int pipeline_front = 0;
    int pipeline_back = 0;
    bool pipeline_overflow = false;
    bool pipeline_underflow = false;

    bool add_to_pipeline(NHttpTransaction* latest);
    NHttpTransaction* take_from_pipeline();
    void delete_pipeline();
};

#endif










