//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// nhttp_flow_data.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_FLOW_DATA_H
#define NHTTP_FLOW_DATA_H

#include <stdio.h>
#include <zlib.h>

#include "stream/stream_api.h"
#include "mime/file_mime_process.h"

#include "nhttp_cutter.h"
#include "nhttp_infractions.h"
#include "nhttp_event_gen.h"

class NHttpTransaction;

class NHttpFlowData : public FlowData
{
public:
    NHttpFlowData();
    ~NHttpFlowData();
    static unsigned nhttp_flow_id;
    static void init() { nhttp_flow_id = FlowData::get_flow_id(); }

    friend class NHttpInspect;
    friend class NHttpMsgSection;
    friend class NHttpMsgStart;
    friend class NHttpMsgRequest;
    friend class NHttpMsgStatus;
    friend class NHttpMsgHeader;
    friend class NHttpMsgHeadShared;
    friend class NHttpMsgTrailer;
    friend class NHttpMsgBody;
    friend class NHttpMsgBodyChunk;
    friend class NHttpMsgBodyCl;
    friend class NHttpMsgBodyOld;
    friend class NHttpStreamSplitter;
    friend class NHttpTransaction;

private:
    // Convenience routines
    void half_reset(NHttpEnums::SourceId source_id);
    void trailer_prep(NHttpEnums::SourceId source_id);

    // 0 element refers to client request, 1 element refers to server response

    // *** StreamSplitter internal data - scan()
    NHttpCutter* cutter[2] = { nullptr, nullptr };

    // *** StreamSplitter internal data - reassemble()
    uint8_t* section_buffer[2] = { nullptr, nullptr };
    uint32_t section_offset[2] = { 0, 0 };
    NHttpEnums::ChunkState chunk_state[2] = { NHttpEnums::CHUNK_NUMBER, NHttpEnums::CHUNK_NUMBER };
    uint32_t chunk_expected_length[2] = { 0, 0 };

    // *** StreamSplitter internal data - scan() => reassemble()
    uint32_t num_excess[2] = { 0, 0 };
    bool is_broken_chunk[2] = { false, false };
    uint32_t num_good_chunks[2] = { 0, 0 };

    // *** StreamSplitter => Inspector (facts about the most recent message section)
    NHttpEnums::SectionType section_type[2] = { NHttpEnums::SEC__NOT_COMPUTE,
                                                NHttpEnums::SEC__NOT_COMPUTE };
    bool tcp_close[2] = { false, false };
    NHttpInfractions infractions[2];
    NHttpEventGen events[2];
    int32_t num_head_lines[2] = { NHttpEnums::STAT_NOT_PRESENT, NHttpEnums::STAT_NOT_PRESENT };

    // *** Inspector => StreamSplitter (facts about the message section that is coming next)
    NHttpEnums::SectionType type_expected[2] = { NHttpEnums::SEC_REQUEST, NHttpEnums::SEC_STATUS };
    // length of the data from Content-Length field
    int64_t data_length[2] = { NHttpEnums::STAT_NOT_PRESENT, NHttpEnums::STAT_NOT_PRESENT };
    uint32_t section_size_target[2] = { 0, 0 };
    uint32_t section_size_max[2] = { 0, 0 };
    NHttpEnums::CompressId compression[2] = { NHttpEnums::CMP_NONE, NHttpEnums::CMP_NONE };
    z_stream* compress_stream[2] = { nullptr, nullptr };
    uint64_t zero_nine_expected = 0;

    // *** Inspector's internal data about the current message
    NHttpEnums::VersionId version_id[2] = { NHttpEnums::VERS__NOT_PRESENT,
                                            NHttpEnums::VERS__NOT_PRESENT };
    NHttpEnums::MethodId method_id = NHttpEnums::METH__NOT_PRESENT;
    int32_t status_code_num = NHttpEnums::STAT_NOT_PRESENT;
    int64_t file_depth_remaining[2] = { NHttpEnums::STAT_NOT_PRESENT,
        NHttpEnums::STAT_NOT_PRESENT };
    int64_t detect_depth_remaining[2] = { NHttpEnums::STAT_NOT_PRESENT,
        NHttpEnums::STAT_NOT_PRESENT };
    MimeSession* mime_state = nullptr;  // SRC_CLIENT only
    uint64_t expected_msg_num[2] = { 1, 1 };

    // number of user data octets seen so far (regular body or chunks)
    int64_t body_octets[2] = { NHttpEnums::STAT_NOT_PRESENT, NHttpEnums::STAT_NOT_PRESENT };

    // Transaction management including pipelining
    // FIXIT-L pipeline deserves to be its own class
    NHttpTransaction* transaction[2] = { nullptr, nullptr };
    static const int MAX_PIPELINE = 100;  // requests seen - responses seen <= MAX_PIPELINE
    NHttpTransaction** pipeline = nullptr;
    int pipeline_front = 0;
    int pipeline_back = 0;
    bool pipeline_overflow = false;
    bool pipeline_underflow = false;

    bool add_to_pipeline(NHttpTransaction* latest);
    NHttpTransaction* take_from_pipeline();
    void delete_pipeline();

#ifdef REG_TEST
    void show(FILE* out_file) const;

    static uint64_t instance_count;
    uint64_t seq_num;
#endif
};

#endif

