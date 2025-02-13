//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_stream.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_STREAM_H
#define HTTP2_STREAM_H

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"
#include "http2_frame.h"

class Http2DataCutter;
class Http2FlowData;
class HttpFlowData;
class HttpMsgSection;

class Http2Stream
{
public:
    Http2Stream(uint32_t stream_id, Http2FlowData* session_data_);
    ~Http2Stream();
    uint32_t get_stream_id() const { return stream_id; }
    void eval_frame(const uint8_t* header_buffer, uint32_t header_len, const uint8_t* data_buffer,
        uint32_t data_len, HttpCommon::SourceId source_id, snort::Packet* p);
    void check_and_cleanup_completed();
    void clear_frame(snort::Packet* p);
    const Field& get_buf(unsigned id);
    HttpFlowData* get_hi_flow_data() const { return hi_flow_data; }
    void set_hi_flow_data(HttpFlowData* flow_data);
    Http2Frame *get_current_frame() { return current_frame; }

    void set_state(HttpCommon::SourceId source_id, Http2Enums::StreamState new_state);
    Http2Enums::StreamState get_state(HttpCommon::SourceId source_id) const
        { return state[source_id]; }
    bool is_open(HttpCommon::SourceId source_id);
    void set_end_stream_on_data_flush(HttpCommon::SourceId source_id)
        { end_stream_on_data_flush[source_id] = true; }
    bool is_end_stream_on_data_flush(HttpCommon::SourceId source_id)
        { return end_stream_on_data_flush[source_id]; }
    void finish_msg_body(HttpCommon::SourceId source_id, bool expect_trailers,
        bool clear_partial_buffer);
    void set_discard(HttpCommon::SourceId source_id)
    { discard[source_id] = true; }
    bool is_discard_set(HttpCommon::SourceId source_id)
    { return discard[source_id]; }

#ifdef REG_TEST
    void print_frame(FILE* output);
#endif

private:
    const uint32_t stream_id;
    Http2FlowData* const session_data;
    Http2Frame* current_frame = nullptr;
    HttpFlowData* hi_flow_data = nullptr;
    bool end_stream_on_data_flush[2] = { false, false };
    Http2Enums::StreamState state[2] =
        { Http2Enums::STREAM_EXPECT_HEADERS, Http2Enums::STREAM_EXPECT_HEADERS };
    bool discard[2] = { false, false };
};

#endif
