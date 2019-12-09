//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "http2_flow_data.h"
#include "http2_frame.h"

class Http2Stream
{
public:
    Http2Stream(Http2FlowData* session_data_);
    ~Http2Stream();
    void eval_frame(const uint8_t* header_buffer, int32_t header_len, const uint8_t* data_buffer,
        int32_t data_len, HttpCommon::SourceId source_id);
    void clear_frame();
    const Field& get_buf(unsigned id);
#ifdef REG_TEST
    void print_frame(FILE* output);
#endif

private:
    Http2FlowData* const session_data;
    Http2Frame* current_frame = nullptr;
};

#endif
