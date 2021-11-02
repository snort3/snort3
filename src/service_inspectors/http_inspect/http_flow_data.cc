//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
// http_flow_data.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_flow_data.h"

#include "decompress/file_decomp.h"
#include "main/snort_debug.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "utils/js_identifier_ctx.h"
#include "utils/js_normalizer.h"

#include "http_cutter.h"
#include "http_common.h"
#include "http_enum.h"
#include "http_module.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_msg_status.h"
#include "http_test_manager.h"
#include "http_transaction.h"
#include "http_uri.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

unsigned HttpFlowData::inspector_id = 0;

#ifdef REG_TEST
uint64_t HttpFlowData::instance_count = 0;
#endif

HttpFlowData::HttpFlowData(Flow* flow) : FlowData(inspector_id)
{
#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
    {
        seq_num = ++instance_count;
        if (!HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
        {
            fprintf(HttpTestManager::get_output_file(),
                "Flow Data construct %" PRIu64 "\n", seq_num);
            fflush(HttpTestManager::get_output_file());
        }
    }
#endif
    HttpModule::increment_peg_counts(PEG_CONCURRENT_SESSIONS);
    if (HttpModule::get_peg_counts(PEG_MAX_CONCURRENT_SESSIONS) <
        HttpModule::get_peg_counts(PEG_CONCURRENT_SESSIONS))
        HttpModule::increment_peg_counts(PEG_MAX_CONCURRENT_SESSIONS);

    Http2FlowData* h2i_flow_data = nullptr;
    if (Http2FlowData::inspector_id != 0)
        h2i_flow_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    if (h2i_flow_data != nullptr)
    {
        for_http2 = true;
        h2_stream_id = h2i_flow_data->get_processing_stream_id();
    }
}

HttpFlowData::~HttpFlowData()
{
#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP) &&
        !HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
    {
        fprintf(HttpTestManager::get_output_file(), "Flow Data destruct %" PRIu64 "\n", seq_num);
        fflush(HttpTestManager::get_output_file());
    }
#endif
    if (HttpModule::get_peg_counts(PEG_CONCURRENT_SESSIONS) > 0)
        HttpModule::decrement_peg_counts(PEG_CONCURRENT_SESSIONS);

#ifndef UNIT_TEST_BUILD
    if (js_ident_ctx)
    {
        update_deallocations(js_ident_ctx->size());
        delete js_ident_ctx;

        debug_log(4, http_trace, TRACE_JS_PROC, nullptr,
            "js_ident_ctx deleted\n");
    }
    if (js_normalizer)
    {
        update_deallocations(JSNormalizer::size());
        delete js_normalizer;

        debug_log(4, http_trace, TRACE_JS_PROC, nullptr,
            "js_normalizer deleted\n");
    }
#endif

    for (int k=0; k <= 1; k++)
    {
        delete infractions[k];
        delete events[k];
        delete[] section_buffer[k];
        delete[] partial_buffer[k];
        update_deallocations(partial_buffer_length[k]);
        delete[] partial_detect_buffer[k];
        update_deallocations(partial_detect_length[k]);
        HttpTransaction::delete_transaction(transaction[k], nullptr);
        delete cutter[k];
        if (compress_stream[k] != nullptr)
        {
            inflateEnd(compress_stream[k]);
            delete compress_stream[k];
            update_deallocations(zlib_inflate_memory);
        }
        if (mime_state[k] != nullptr)
        {
            delete mime_state[k];
        }
    }

    delete utf_state;
    if (fd_state != nullptr)
        File_Decomp_StopFree(fd_state);
    delete_pipeline();

    while (discard_list != nullptr)
    {
        HttpTransaction* tmp = discard_list;
        discard_list = discard_list->next;
        delete tmp;
    }
}

size_t HttpFlowData::size_of()
{
    return sizeof(HttpFlowData) + (2 * sizeof(HttpEventGen));
}

void HttpFlowData::half_reset(SourceId source_id)
{
    assert((source_id == SRC_CLIENT) || (source_id == SRC_SERVER));

    version_id[source_id] = VERS__NOT_PRESENT;
    data_length[source_id] = STAT_NOT_PRESENT;
    body_octets[source_id] = STAT_NOT_PRESENT;
    file_octets[source_id] = STAT_NOT_PRESENT;
    publish_octets[source_id] = STAT_NOT_PRESENT;
    partial_inspected_octets[source_id] = 0;
    section_size_target[source_id] = 0;
    stretch_section_to_packet[source_id] = false;
    accelerated_blocking[source_id] = false;
    file_depth_remaining[source_id] = STAT_NOT_PRESENT;
    detect_depth_remaining[source_id] = STAT_NOT_PRESENT;
    publish_depth_remaining[source_id] = STAT_NOT_PRESENT;
    detection_status[source_id] = DET_REACTIVATING;

    compression[source_id] = CMP_NONE;
    if (compress_stream[source_id] != nullptr)
    {
        inflateEnd(compress_stream[source_id]);
        delete compress_stream[source_id];
        compress_stream[source_id] = nullptr;
        update_deallocations(zlib_inflate_memory);
    }
    if (mime_state[source_id] != nullptr)
    {
        delete mime_state[source_id];
        mime_state[source_id] = nullptr;
    }
    delete infractions[source_id];
    infractions[source_id] = new HttpInfractions;
    section_offset[source_id] = 0;
    chunk_state[source_id] = CHUNK_NEWLINES;
    chunk_expected_length[source_id] = 0;

    if (source_id == SRC_CLIENT)
    {
        type_expected[SRC_CLIENT] = SEC_REQUEST;
        expected_trans_num[SRC_CLIENT]++;
        method_id = METH__NOT_PRESENT;
    }
    else
    {
        type_expected[SRC_SERVER] = SEC_STATUS;
        if (transaction[SRC_SERVER]->final_response())
            expected_trans_num[SRC_SERVER]++;
        status_code_num = STAT_NOT_PRESENT;
        delete utf_state;
        utf_state = nullptr;
        if (fd_state != nullptr)
        {
            File_Decomp_StopFree(fd_state);
            fd_state = nullptr;
        }
    }
}

void HttpFlowData::trailer_prep(SourceId source_id)
{
    type_expected[source_id] = SEC_TRAILER;
    compression[source_id] = CMP_NONE;
    if (compress_stream[source_id] != nullptr)
    {
        inflateEnd(compress_stream[source_id]);
        delete compress_stream[source_id];
        compress_stream[source_id] = nullptr;
        update_deallocations(zlib_inflate_memory);
    }
    detection_status[source_id] = DET_REACTIVATING;
}

void HttpFlowData::garbage_collect()
{
    HttpTransaction** current = &discard_list;
    while (*current != nullptr)
    {
        if ((*current)->is_clear())
        {
            HttpTransaction* tmp = *current;
            *current = (*current)->next;
            delete tmp;
        }
        else
            current = &(*current)->next;
    }
}

#ifndef UNIT_TEST_BUILD
void HttpFlowData::reset_js_pdu_idx()
{
    js_pdu_idx = pdu_idx = 0;
    js_data_lost_once = false;
}

void HttpFlowData::reset_js_ident_ctx()
{
    if (js_ident_ctx)
    {
        js_ident_ctx->reset();
        debug_log(4, http_trace, TRACE_JS_PROC, nullptr,
            "js_ident_ctx reset\n");
    }
}

snort::JSNormalizer& HttpFlowData::acquire_js_ctx(int32_t ident_depth, size_t norm_depth,
    uint8_t max_template_nesting, uint32_t max_scope_depth,
    const std::unordered_set<std::string>& built_in_ident)
{
    if (js_normalizer)
        return *js_normalizer;

    if (!js_ident_ctx)
    {
        js_ident_ctx = new JSIdentifierCtx(ident_depth, built_in_ident);
        update_allocations(js_ident_ctx->size());

        debug_logf(4, http_trace, TRACE_JS_PROC, nullptr,
            "js_ident_ctx created (ident_depth %d)\n", ident_depth);
    }

    js_normalizer = new JSNormalizer(*js_ident_ctx, norm_depth,
        max_template_nesting, max_scope_depth);
    update_allocations(JSNormalizer::size());

    debug_logf(4, http_trace, TRACE_JS_PROC, nullptr,
        "js_normalizer created (norm_depth %zd, max_template_nesting %d)\n",
        norm_depth, max_template_nesting);

    return *js_normalizer;
}

bool HttpFlowData::is_pdu_missed()
{
    bool pdu_missed = ((pdu_idx - js_pdu_idx) > 1);
    js_pdu_idx = pdu_idx;
    return pdu_missed;
}

void HttpFlowData::release_js_ctx()
{
    js_continue = false;

    if (!js_normalizer)
        return;

    update_deallocations(JSNormalizer::size());
    delete js_normalizer;
    js_normalizer = nullptr;

    debug_log(4, http_trace, TRACE_JS_PROC, nullptr,
        "js_normalizer deleted\n");
}
#else
void HttpFlowData::reset_js_ident_ctx() {}
snort::JSNormalizer& HttpFlowData::acquire_js_ctx(int32_t, size_t, uint8_t, uint32_t,
    const std::unordered_set<std::string>&)
{ return *js_normalizer; }
void HttpFlowData::release_js_ctx() {}
#endif

bool HttpFlowData::add_to_pipeline(HttpTransaction* latest)
{
    if (pipeline == nullptr)
    {
        pipeline = new HttpTransaction*[MAX_PIPELINE];
        HttpModule::increment_peg_counts(PEG_PIPELINED_FLOWS);
        update_allocations(sizeof(HttpTransaction*) * MAX_PIPELINE);
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
    HttpModule::increment_peg_counts(PEG_PIPELINED_REQUESTS);
    return true;
}

HttpTransaction* HttpFlowData::take_from_pipeline()
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

void HttpFlowData::delete_pipeline()
{
    for (int k=pipeline_front; k != pipeline_back; k = (k+1) % MAX_PIPELINE)
    {
        delete pipeline[k];
    }
    if (pipeline != nullptr)
        update_deallocations(sizeof(HttpTransaction*) * MAX_PIPELINE);
    delete[] pipeline;
}

HttpInfractions* HttpFlowData::get_infractions(SourceId source_id)
{
    if (infractions[source_id] != nullptr)
        return infractions[source_id];
    assert(transaction[source_id] != nullptr);
    assert(transaction[source_id]->get_infractions(source_id) != nullptr);
    return transaction[source_id]->get_infractions(source_id);
}

void HttpFlowData::finish_h2_body(HttpCommon::SourceId source_id, HttpEnums::H2BodyState state,
    bool clear_partial_buffer)
{
    assert((h2_body_state[source_id] == H2_BODY_NOT_COMPLETE) ||
        (h2_body_state[source_id] == H2_BODY_LAST_SEG));
    h2_body_state[source_id] = state;
    partial_flush[source_id] = false;
    if (clear_partial_buffer)
    {
        // We've already sent all data through detection so no need to reinspect. Just need to
        // prep for trailers
        update_deallocations(partial_buffer_length[source_id]);
        partial_buffer_length[source_id] = 0;
        delete[] partial_buffer[source_id];
        partial_buffer[source_id] = nullptr;

        update_deallocations(partial_detect_length[source_id]);
        partial_detect_length[source_id] = 0;
        delete[] partial_detect_buffer[source_id];
        partial_detect_buffer[source_id] = nullptr;

        body_octets[source_id] += partial_inspected_octets[source_id];
        partial_inspected_octets[source_id] = 0;
    }
}

uint32_t HttpFlowData::get_h2_stream_id() const
{
    return h2_stream_id;
}

#ifdef REG_TEST
void HttpFlowData::show(FILE* out_file) const
{
    assert(out_file != nullptr);
    fprintf(out_file, "Diagnostic output from HttpFlowData (Client/Server):\n");
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
    fprintf(out_file, "File octets: %" PRIi64 "/%" PRIi64 "\n", file_octets[0], file_octets[1]);
    fprintf(out_file, "Pipelining: front %d back %d overflow %d underflow %d\n", pipeline_front,
        pipeline_back, pipeline_overflow, pipeline_underflow);
    fprintf(out_file, "Cutter: %s/%s\n", (cutter[0] != nullptr) ? "Present" : "nullptr",
        (cutter[1] != nullptr) ? "Present" : "nullptr");
    fprintf(out_file, "utf_state: %s\n", (utf_state != nullptr) ? "Present" : "nullptr");
    fprintf(out_file, "fd_state: %s\n", (fd_state != nullptr) ? "Present" : "nullptr");
    fprintf(out_file, "mime_state: %s/%s\n", (mime_state[0] != nullptr) ? "Present" : "nullptr",
        (mime_state[1] != nullptr) ? "Present" : "nullptr");
}
#endif

