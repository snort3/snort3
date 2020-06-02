//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
    uint32_t get_stream_id() { return stream_id; }
    void eval_frame(const uint8_t* header_buffer, int32_t header_len, const uint8_t* data_buffer,
        int32_t data_len, HttpCommon::SourceId source_id);
    void clear_frame();
    const Field& get_buf(unsigned id);
    HttpFlowData* get_hi_flow_data() const { return hi_flow_data; }
    void set_hi_flow_data(HttpFlowData* flow_data);
    HttpMsgSection* get_hi_msg_section() const { return hi_msg_section; }
    void set_hi_msg_section(HttpMsgSection* section) { hi_msg_section = section; }
    uint32_t get_xtradata_mask() { return (current_frame != nullptr) ?
        current_frame->get_xtradata_mask() : 0; }
    Http2Frame *get_current_frame() { return current_frame; }

    Http2DataCutter* get_data_cutter(HttpCommon::SourceId source_id);
    void set_data_cutter(Http2DataCutter* cutter, HttpCommon::SourceId source_id)
        { data_cutter[source_id] = cutter; }

    void set_partial_buf_pending(HttpCommon::SourceId source_id)
    { partial_buf_pending[source_id] = true; }
    void reset_partial_buf_pending(HttpCommon::SourceId source_id)
    { partial_buf_pending[source_id] = false; }
    bool is_partial_buf_pending(HttpCommon::SourceId source_id)
    { return partial_buf_pending[source_id]; }

    void set_state(HttpCommon::SourceId source_id, Http2Enums::StreamState new_state) 
        { state[source_id] = new_state; }
    Http2Enums::StreamState get_state(HttpCommon::SourceId source_id) { return state[source_id]; }
    bool is_open(HttpCommon::SourceId source_id);
    void set_last_data_flush(HttpCommon::SourceId source_id) { last_data_flush[source_id] = true; }
    bool is_last_data_flush(HttpCommon::SourceId source_id) { return last_data_flush[source_id]; }

#ifdef REG_TEST
    void print_frame(FILE* output);
#endif

private:
    const uint32_t stream_id;
    Http2FlowData* const session_data;
    Http2Frame* current_frame = nullptr;
    HttpFlowData* hi_flow_data = nullptr;
    HttpMsgSection* hi_msg_section = nullptr;
    Http2DataCutter* data_cutter[2] = { nullptr, nullptr};
    bool partial_buf_pending[2] = { false, false }; // used to indicate a partial buffer
    bool last_data_flush[2] = { false, false };
    Http2Enums::StreamState state[2] = { Http2Enums::STATE_IDLE, Http2Enums::STATE_IDLE };
};

#endif
