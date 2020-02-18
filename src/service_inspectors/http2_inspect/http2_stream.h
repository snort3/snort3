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

#include "http2_frame.h"

class HttpFlowData;
class Http2FlowData;
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
    void set_hi_flow_data(HttpFlowData* flow_data)
        { assert(hi_flow_data == nullptr); hi_flow_data = flow_data; }
    HttpMsgSection* get_hi_msg_section() const { return hi_msg_section; }
    void set_hi_msg_section(HttpMsgSection* section) { hi_msg_section = section; }
    uint32_t get_xtradata_mask() { return (current_frame != nullptr) ? 
        current_frame->get_xtradata_mask() : 0; }
    Http2Frame *get_current_frame() { return current_frame; }
#ifdef REG_TEST
    void print_frame(FILE* output);
#endif

private:
    const uint32_t stream_id;
    Http2FlowData* const session_data;
    Http2Frame* current_frame = nullptr;
    HttpFlowData* hi_flow_data = nullptr;
    HttpMsgSection* hi_msg_section = nullptr;
};

#endif
