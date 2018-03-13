//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow.h"
#include "stream/stream_splitter.h"
#include "http2_enum.h"

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
        const uint8_t*, unsigned, uint32_t, unsigned&, Http2Enums::SourceId);
    friend snort::StreamSplitter::Status implement_scan(Http2FlowData*, const uint8_t*, uint32_t,
        uint32_t*, Http2Enums::SourceId);
    friend bool implement_get_buf(unsigned id, Http2FlowData*, Http2Enums::SourceId,
        snort::InspectionBuffer&);

protected:
    // 0 element refers to client frame, 1 element refers to server frame
    bool preface[2] = { true, false };
    bool header_coming[2]  = { false, false };
    uint8_t* frame_header[2] = { nullptr, nullptr };
    uint8_t* frame[2] = { nullptr, nullptr };
    uint32_t frame_size[2] = { 0, 0 };
    uint8_t* frame_data[2] = { nullptr, nullptr };
    uint32_t frame_data_size[2] = { 0, 0 };
    uint32_t leftover_data[2] = { 0, 0 };
    uint32_t octets_seen[2] = { 0, 0 };
    bool frame_in_detection = false;
};

#endif

