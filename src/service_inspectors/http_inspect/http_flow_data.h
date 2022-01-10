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
// http_flow_data.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_FLOW_DATA_H
#define HTTP_FLOW_DATA_H

#include <zlib.h>

#include <cstdio>

#include "flow/flow.h"
#include "mime/file_mime_process.h"
#include "utils/util_utf.h"
#include "decompress/file_decomp.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_event.h"

class HttpTransaction;
class HttpJsNorm;
class HttpMsgSection;
class HttpCutter;
class HttpQueryParser;
class JSIdentifierCtxBase;

namespace snort
{
class JSNormalizer;
}

class HttpFlowData : public snort::FlowData
{
public:
    HttpFlowData(snort::Flow* flow);
    ~HttpFlowData() override;
    static unsigned inspector_id;
    static void init() { inspector_id = snort::FlowData::create_flow_data_id(); }

    friend class HttpBodyCutter;
    friend class HttpInspect;
    friend class HttpJsNorm;
    friend class HttpMsgSection;
    friend class HttpMsgStart;
    friend class HttpMsgRequest;
    friend class HttpMsgStatus;
    friend class HttpMsgHeader;
    friend class HttpMsgHeadShared;
    friend class HttpMsgTrailer;
    friend class HttpMsgBody;
    friend class HttpMsgBodyChunk;
    friend class HttpMsgBodyCl;
    friend class HttpMsgBodyH2;
    friend class HttpMsgBodyOld;
    friend class HttpQueryParser;
    friend class HttpStreamSplitter;
    friend class HttpTransaction;
#if defined(REG_TEST) || defined(UNIT_TEST)
    friend class HttpUnitTestSetup;
#endif

    HttpEnums::SectionType get_type_expected(HttpCommon::SourceId source_id) const
    { return type_expected[source_id]; }

    void finish_h2_body(HttpCommon::SourceId source_id, HttpEnums::H2BodyState state,
        bool clear_partial_buffer);

    void set_h2_body_state(HttpCommon::SourceId source_id, HttpEnums::H2BodyState state)
    { h2_body_state[source_id] = state; }

    uint32_t get_h2_stream_id() const;

    HttpEnums::VersionId get_version_id(HttpCommon::SourceId source_id) const
    { return version_id[source_id]; }

private:
    // HTTP/2 handling
    bool for_http2 = false;
    HttpEnums::H2BodyState h2_body_state[2] = { HttpEnums::H2_BODY_NOT_COMPLETE,
         HttpEnums::H2_BODY_NOT_COMPLETE };
    uint32_t h2_stream_id = 0;

    // Convenience routines
    void half_reset(HttpCommon::SourceId source_id);
    void trailer_prep(HttpCommon::SourceId source_id);
    void garbage_collect();

    // 0 element refers to client request, 1 element refers to server response

    // *** StreamSplitter internal data - scan()
    HttpCutter* cutter[2] = { nullptr, nullptr };

    // *** StreamSplitter internal data - reassemble()
    uint8_t* section_buffer[2] = { nullptr, nullptr };
    uint32_t section_offset[2] = { 0, 0 };
    uint32_t chunk_expected_length[2] = { 0, 0 };
    uint32_t running_total[2] = { 0, 0 };
    HttpEnums::ChunkState chunk_state[2] = { HttpEnums::CHUNK_NEWLINES,
        HttpEnums::CHUNK_NEWLINES };
    uint32_t partial_raw_bytes[2] = { 0, 0 };
    uint8_t* partial_buffer[2] = { nullptr, nullptr };
    uint32_t partial_buffer_length[2] = { 0, 0 };

    // *** StreamSplitter internal data - scan() => reassemble()
    uint32_t num_excess[2] = { 0, 0 };
    uint32_t num_good_chunks[2] = { 0, 0 };
    uint32_t octets_expected[2] = { 0, 0 };
    bool is_broken_chunk[2] = { false, false };

    // *** StreamSplitter => Inspector (facts about the most recent message section)
    HttpEnums::SectionType section_type[2] = { HttpEnums::SEC__NOT_COMPUTE,
                                                HttpEnums::SEC__NOT_COMPUTE };
    int32_t octets_reassembled[2] = { HttpCommon::STAT_NOT_PRESENT, HttpCommon::STAT_NOT_PRESENT };
    int32_t num_head_lines[2] = { HttpCommon::STAT_NOT_PRESENT, HttpCommon::STAT_NOT_PRESENT };
    bool tcp_close[2] = { false, false };
    bool partial_flush[2] = { false, false };
    uint64_t last_connect_trans_w_early_traffic = 0;

    HttpInfractions* infractions[2] = { new HttpInfractions, new HttpInfractions };
    HttpEventGen* events[2] = { new HttpEventGen, new HttpEventGen };

    // Infractions are associated with a specific message and are stored in the transaction for
    // that message. But StreamSplitter splits the start line before there is a transaction and
    // needs a place to put the problems it finds. Hence infractions are created before there is a
    // transaction to associate them with and stored here until attach_my_transaction() takes them
    // away and resets these to nullptr. The accessor method hides this from StreamSplitter.
    HttpInfractions* get_infractions(HttpCommon::SourceId source_id);

    // *** Inspector => StreamSplitter (facts about the message section that is coming next)
    HttpEnums::SectionType type_expected[2] = { HttpEnums::SEC_REQUEST, HttpEnums::SEC_STATUS };
    uint64_t last_request_was_connect = false;
    z_stream* compress_stream[2] = { nullptr, nullptr };
    uint64_t zero_nine_expected = 0;
    // length of the data from Content-Length field
    int64_t data_length[2] = { HttpCommon::STAT_NOT_PRESENT, HttpCommon::STAT_NOT_PRESENT };
    uint32_t section_size_target[2] = { 0, 0 };
    HttpEnums::CompressId compression[2] = { HttpEnums::CMP_NONE, HttpEnums::CMP_NONE };
    HttpEnums::DetectionStatus detection_status[2] = { HttpEnums::DET_ON, HttpEnums::DET_ON };
    bool stretch_section_to_packet[2] = { false, false };
    bool accelerated_blocking[2] = { false, false };

    // *** Inspector's internal data about the current message
    struct FdCallbackContext
    {
        HttpInfractions* infractions = nullptr;
        HttpEventGen* events = nullptr;
    };
    FdCallbackContext fd_alert_context; // SRC_SERVER only
    snort::MimeSession* mime_state[2] = { nullptr, nullptr };
    snort::UtfDecodeSession* utf_state = nullptr; // SRC_SERVER only
    fd_session_t* fd_state = nullptr; // SRC_SERVER only
    int64_t file_depth_remaining[2] = { HttpCommon::STAT_NOT_PRESENT,
        HttpCommon::STAT_NOT_PRESENT };
    int64_t detect_depth_remaining[2] = { HttpCommon::STAT_NOT_PRESENT,
        HttpCommon::STAT_NOT_PRESENT };
    int32_t publish_depth_remaining[2] = { HttpCommon::STAT_NOT_PRESENT,
        HttpCommon::STAT_NOT_PRESENT };
    int32_t file_decomp_buffer_size_remaining[2] = { HttpCommon::STAT_NOT_PRESENT,
        HttpCommon::STAT_NOT_PRESENT };
    uint64_t expected_trans_num[2] = { 1, 1 };

    // number of user data octets seen so far (regular body or chunks)
    int64_t body_octets[2] = { HttpCommon::STAT_NOT_PRESENT, HttpCommon::STAT_NOT_PRESENT };
    // normalized octets forwarded to file or MIME processing
    int64_t file_octets[2] = { HttpCommon::STAT_NOT_PRESENT, HttpCommon::STAT_NOT_PRESENT };
    int32_t publish_octets[2] = { HttpCommon::STAT_NOT_PRESENT, HttpCommon::STAT_NOT_PRESENT };
    uint32_t partial_inspected_octets[2] = { 0, 0 };
    uint8_t* partial_detect_buffer[2] = { nullptr, nullptr };
    uint32_t partial_detect_length[2] = { 0, 0 };
    uint32_t partial_js_detect_length[2] = { 0, 0 };
    int32_t status_code_num = HttpCommon::STAT_NOT_PRESENT;
    HttpEnums::VersionId version_id[2] = { HttpEnums::VERS__NOT_PRESENT,
                                            HttpEnums::VERS__NOT_PRESENT };
    HttpEnums::MethodId method_id = HttpEnums::METH__NOT_PRESENT;

    // *** Transaction management including pipelining
    static const int MAX_PIPELINE = 100;  // requests seen - responses seen <= MAX_PIPELINE
    HttpTransaction* transaction[2] = { nullptr, nullptr };
    HttpTransaction** pipeline = nullptr;
    int16_t pipeline_front = 0;
    int16_t pipeline_back = 0;
    uint32_t pdu_idx = 0;
    uint32_t js_pdu_idx = 0;
    bool js_data_lost_once = false;
    bool pipeline_overflow = false;
    bool pipeline_underflow = false;

    bool add_to_pipeline(HttpTransaction* latest);
    HttpTransaction* take_from_pipeline();
    void delete_pipeline();

    // Transactions with uncleared sections awaiting deletion
    HttpTransaction* discard_list = nullptr;


    // Memory footprint required by zlib inflation. Formula from https://zlib.net/zlib_tech.html
    // Accounts for a 32k sliding window and 11520 bytes of inflate_huft allocations
    static const size_t zlib_inflate_memory = (1 << 15) + 1440*2*sizeof(int);

    // *** HttpJsNorm
    JSIdentifierCtxBase* js_ident_ctx = nullptr;
    snort::JSNormalizer* js_normalizer = nullptr;
    bool js_continue = false;
    bool js_built_in_event = false;

    void reset_js_pdu_idx();
    void reset_js_ident_ctx();
    snort::JSNormalizer& acquire_js_ctx(int32_t ident_depth, size_t norm_depth,
        uint8_t max_template_nesting, uint32_t max_bracket_depth, uint32_t max_scope_depth,
        const std::unordered_set<std::string>& ignored_ids);
    void release_js_ctx();
    bool is_pdu_missed();

    bool cutover_on_clear = false;
    bool ssl_search_abandoned = false;

#ifdef REG_TEST
    static uint64_t instance_count;
    uint64_t seq_num;

    void show(FILE* out_file) const;
#endif
};

#endif

