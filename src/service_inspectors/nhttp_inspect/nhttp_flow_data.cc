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
// nhttp_flow_data.cc author Tom Peters <thopeter@cisco.com>

#include "nhttp_enum.h"
#include "nhttp_test_manager.h"
#include "nhttp_flow_data.h"
#include "nhttp_transaction.h"

using namespace NHttpEnums;

unsigned NHttpFlowData::nhttp_flow_id = 0;

#ifdef REG_TEST
uint64_t NHttpFlowData::instance_count = 0;
#endif

NHttpFlowData::NHttpFlowData() : FlowData(nhttp_flow_id)
{
#ifdef REG_TEST
    if (NHttpTestManager::use_test_output())
    {
        seq_num = ++instance_count;
        if (!NHttpTestManager::use_test_input())
        {
            printf("Flow Data construct %" PRIu64 "\n", seq_num);
            fflush(nullptr);
        }
    }
#endif
}

NHttpFlowData::~NHttpFlowData()
{
#ifdef REG_TEST
    if (!NHttpTestManager::use_test_input() && NHttpTestManager::use_test_output())
    {
        printf("Flow Data destruct %" PRIu64 "\n", seq_num);
        fflush(nullptr);
    }
#endif
    for (int k=0; k <= 1; k++)
    {
        if ((section_type[k] != SEC_BODY_CHUNK) &&
            (section_type[k] != SEC_BODY_CL) &&
            (section_type[k] != SEC_BODY_OLD))
            // Body sections are reassembled in a static buffer
            delete[] section_buffer[k];
        delete transaction[k];
        delete cutter[k];
        if (compress_stream[k] != nullptr)
        {
            inflateEnd(compress_stream[k]);
            delete compress_stream[k];
        }
    }

    if (mime_state != nullptr)
    {
        delete mime_state;
    }

    delete_pipeline();
}

void NHttpFlowData::half_reset(SourceId source_id)
{
    assert((source_id == SRC_CLIENT) || (source_id == SRC_SERVER));

    version_id[source_id] = VERS__NOT_PRESENT;
    data_length[source_id] = STAT_NOT_PRESENT;
    body_octets[source_id] = STAT_NOT_PRESENT;
    section_size_target[source_id] = 0;
    section_size_max[source_id] = 0;
    file_depth_remaining[source_id] = STAT_NOT_PRESENT;
    detect_depth_remaining[source_id] = STAT_NOT_PRESENT;
    compression[source_id] = CMP_NONE;
    if (compress_stream[source_id] != nullptr)
    {
        inflateEnd(compress_stream[source_id]);
        delete compress_stream[source_id];
        compress_stream[source_id] = nullptr;
    }
    infractions[source_id].reset();
    events[source_id].reset();
    section_offset[source_id] = 0;
    chunk_state[source_id] = CHUNK_NUMBER;
    chunk_expected_length[source_id] = 0;

    if (source_id == SRC_CLIENT)
    {
        type_expected[SRC_CLIENT] = SEC_REQUEST;
        expected_msg_num[SRC_CLIENT]++;
        method_id = METH__NOT_PRESENT;
        if (mime_state != nullptr)
        {
            delete mime_state;
            mime_state = nullptr;
        }
    }
    else
    {
        type_expected[SRC_SERVER] = SEC_STATUS;
        expected_msg_num[SRC_SERVER]++;
        status_code_num = STAT_NOT_PRESENT;
    }
}

void NHttpFlowData::trailer_prep(SourceId source_id)
{
    type_expected[source_id] = SEC_TRAILER;
    compression[source_id] = CMP_NONE;
    if (compress_stream[source_id] != nullptr)
    {
        inflateEnd(compress_stream[source_id]);
        delete compress_stream[source_id];
        compress_stream[source_id] = nullptr;
    }
    infractions[source_id].reset();
    events[source_id].reset();
}

bool NHttpFlowData::add_to_pipeline(NHttpTransaction* latest)
{
    if (pipeline == nullptr)
    {
        pipeline = new NHttpTransaction*[MAX_PIPELINE];
    }
    assert(!pipeline_overflow && !pipeline_underflow);
    int new_back = (pipeline_back+1) % MAX_PIPELINE;
    if (new_back == pipeline_front)
    {
        pipeline_overflow = true;
        return false;
    }
    pipeline[pipeline_back] = latest;
    pipeline_back = new_back;
    return true;
}

NHttpTransaction* NHttpFlowData::take_from_pipeline()
{
    assert(!pipeline_underflow);
    if (pipeline_back == pipeline_front)
    {
        return nullptr;
    }
    int old_front = pipeline_front;
    pipeline_front = (pipeline_front+1) % MAX_PIPELINE;
    return pipeline[old_front];
}

void NHttpFlowData::delete_pipeline()
{
    for (int k=pipeline_front; k != pipeline_back; k = (k+1) % MAX_PIPELINE)
    {
        delete pipeline[k];
    }
    delete[] pipeline;
}

#ifdef REG_TEST
void NHttpFlowData::show(FILE* out_file) const
{
    assert(out_file != nullptr);
    fprintf(out_file, "Diagnostic output from NHttpFlowData (Client/Server):\n");
    fprintf(out_file, "Version ID: %d/%d\n", version_id[0], version_id[1]);
    fprintf(out_file, "Method ID: %d\n", method_id);
    fprintf(out_file, "Status code: %d\n", status_code_num);
    fprintf(out_file, "Type expected: %d/%d\n", type_expected[0], type_expected[1]);
    fprintf(out_file, "Data length: %" PRIi64 "/%" PRIi64 "\n", data_length[0], data_length[1]);
    fprintf(out_file, "Detect depth remaining: %" PRIi64 "/%" PRIi64 "\n",
        detect_depth_remaining[0], detect_depth_remaining[1]);
    fprintf(out_file, "File depth remaining: %" PRIi64 "/%" PRIi64 "\n", file_depth_remaining[0],
        file_depth_remaining[1]);
    fprintf(out_file, "Body octets: %" PRIi64 "/%" PRIi64 "\n", body_octets[0], body_octets[1]);
    fprintf(out_file, "Pipelining: front %d back %d overflow %d underflow %d\n", pipeline_front,
        pipeline_back, pipeline_overflow, pipeline_underflow);
}
#endif

