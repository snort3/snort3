//--------------------------------------------------------------------------
// Copyright (C) 2018-2019 Cisco and/or its affiliates. All rights reserved.
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
// http2_flow_data.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_FLOW_DATA_H
#define HTTP2_FLOW_DATA_H

#include <vector>

#include "main/snort_types.h"
#include "utils/event_gen.h"
#include "utils/infractions.h"
#include "flow/flow.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "stream/stream_splitter.h"

#include "http2_enum.h"
#include "http2_hpack_int_decode.h"
#include "http2_hpack_string_decode.h"

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;

using Http2EventGen = EventGen<Http2Enums::EVENT__MAX_VALUE, Http2Enums::EVENT__NONE,
    Http2Enums::HTTP2_GID>;

class Http2FlowData : public snort::FlowData
{
public:
    Http2FlowData();
    ~Http2FlowData() override;
    static unsigned inspector_id;
    static void init() { inspector_id = snort::FlowData::create_flow_data_id(); }

    friend class Http2Inspect;
    friend class Http2StreamSplitter;
    friend const snort::StreamBuffer implement_reassemble(Http2FlowData*, unsigned, unsigned,
        const uint8_t*, unsigned, uint32_t, HttpCommon::SourceId);
    friend snort::StreamSplitter::Status implement_scan(Http2FlowData*, const uint8_t*, uint32_t,
        uint32_t*, HttpCommon::SourceId);
    friend bool implement_get_buf(unsigned id, Http2FlowData*, HttpCommon::SourceId,
        snort::InspectionBuffer&);
    friend bool decode_headers(Http2FlowData* session_data, HttpCommon::SourceId source_id,
        const uint8_t* raw_header_buffer, const uint32_t header_length);
    friend bool decode_header_line(Http2FlowData* session_data, HttpCommon::SourceId source_id,
        const uint8_t* encoded_header_buffer, const uint32_t encoded_header_buffer_length,
        uint32_t& bytes_consumed, uint8_t* decoded_header_buffer,
        const uint32_t decoded_header_buffer_length, uint32_t& bytes_written);
    friend bool handle_dynamic_size_update(Http2FlowData* session_data,
        HttpCommon::SourceId source_id, const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const Http2HpackIntDecode &decode_int,
        uint32_t &bytes_consumed, uint32_t &bytes_written);
    friend bool decode_literal_header_line(Http2FlowData* session_data,
         HttpCommon::SourceId source_id, const uint8_t* encoded_header_buffer,
         const uint32_t encoded_header_buffer_length,
        const uint8_t name_index_mask, const Http2HpackIntDecode &decode_int,
        uint32_t &bytes_consumed, uint8_t* decoded_header_buffer,
        const uint32_t decoded_header_buffer_length, uint32_t &bytes_written);
    friend bool decode_index(Http2FlowData* session_data, HttpCommon::SourceId source_id,
        const uint8_t* encoded_header_buffer, const uint32_t encoded_header_length,
        const Http2HpackIntDecode &decode_int, uint32_t &bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t &bytes_written);
    friend bool decode_string_literal(Http2FlowData* session_data, HttpCommon::SourceId source_id,
        const uint8_t* encoded_header_buffer, const uint32_t encoded_header_length,
        const Http2HpackStringDecode &decode_string, bool is_field_name, uint32_t &bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_buffer_length,
        uint32_t &bytes_written);
    friend bool write_decoded_headers(Http2FlowData* session_data, HttpCommon::SourceId source_id,
        const uint8_t* in_buffer, const uint32_t in_length,
        uint8_t* decoded_header_buffer, uint32_t decoded_header_buffer_length,
        uint32_t &bytes_written);

    size_t size_of() override
    { return sizeof(*this); }

protected:
    // 0 element refers to client frame, 1 element refers to server frame
    bool preface[2] = { true, false };
    uint8_t* frame_header[2] = { nullptr, nullptr };
    uint32_t frame_header_size[2] = { 0, 0 };
    uint8_t* frame_data[2] = { nullptr, nullptr };
    uint32_t frame_data_size[2] = { 0, 0 };
    uint8_t* http2_decoded_header[2] = { nullptr, nullptr };
    uint32_t http2_decoded_header_size[2] = { 0, 0 };
    bool frame_in_detection = false;

    // Internal to scan
    bool continuation_expected[2] = { false, false };
    uint8_t currently_processing_frame_header[2][Http2Enums::FRAME_HEADER_LENGTH];
    uint32_t inspection_section_length[2] = { 0, 0 };
    uint32_t leftover_data[2] = { 0, 0 };

    // Used internally by scan and reassemble
    uint32_t octets_seen[2] = { 0, 0 };
    uint8_t header_octets_seen[2] = { 0, 0 };

    // Scan signals to reassemble
    bool header_coming[2]  = { false, false };
    bool payload_discard[2] = { false, false };
    uint32_t frames_aggregated[2] = { 0, 0 };
    
    // Internal to reassemble
    uint32_t remaining_octets_to_next_header[2] = { 0, 0 };
    uint32_t remaining_frame_data_octets[2] = { 0, 0 };
    uint32_t remaining_frame_data_offset[2] = { 0, 0 };
    uint32_t frame_header_offset[2] = { 0, 0 };

    // These will eventually be moved over to the frame/stream object, as they are moved to the
    // transaction in NHI. Also as in NHI accessor methods will need to be added.
    Http2Infractions* infractions[2] = { new Http2Infractions, new Http2Infractions };
    Http2EventGen* events[2] = { new Http2EventGen, new Http2EventGen };

#ifdef REG_TEST
    static uint64_t instance_count;
    uint64_t seq_num;
#endif
};

#endif

