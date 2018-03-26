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

// http2_flow_data_test.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_FLOW_DATA_TEST_H
#define HTTP2_FLOW_DATA_TEST_H

#include "service_inspectors/http2_inspect/http2_enum.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "service_inspectors/http2_inspect/http2_module.h"

// Stubs whose sole purpose is to make the test code link
snort::FlowData::FlowData(unsigned u, Inspector* ph) : next(nullptr), prev(nullptr), handler(ph), id(u) {}
snort::FlowData::~FlowData() = default;
unsigned snort::FlowData::flow_data_id = 0;
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }
void show_stats(SimpleStats*, const char*) { }

class Http2FlowDataTest : public Http2FlowData
{
public:
    bool get_preface(Http2Enums::SourceId source_id) { return preface[source_id]; }
    void set_preface(bool value, Http2Enums::SourceId source_id) { preface[source_id] = value; }
    bool get_header_coming(Http2Enums::SourceId source_id) { return header_coming[source_id]; }
    void set_header_coming(bool value, Http2Enums::SourceId source_id)
        { header_coming[source_id] = value; }
    uint8_t* get_frame_header(Http2Enums::SourceId source_id) { return frame_header[source_id]; }
    void set_frame_header(uint8_t* value, Http2Enums::SourceId source_id)
        { frame_header[source_id] = value; }
    uint8_t* get_frame(Http2Enums::SourceId source_id) { return frame[source_id]; }
    void set_frame(uint8_t* value, Http2Enums::SourceId source_id) { frame[source_id] = value; }
    uint32_t get_frame_size(Http2Enums::SourceId source_id) { return frame_size[source_id]; }
    void set_frame_size(uint32_t value, Http2Enums::SourceId source_id)
        { frame_size[source_id] = value; }
    uint8_t* get_frame_data(Http2Enums::SourceId source_id) { return frame_data[source_id]; }
    void set_frame_data(uint8_t* value, Http2Enums::SourceId source_id)
        { frame_data[source_id] = value; }
    uint32_t get_frame_data_size(Http2Enums::SourceId source_id)
        { return frame_data_size[source_id]; }
    void set_frame_data_size(uint32_t value, Http2Enums::SourceId source_id)
        { frame_data_size[source_id] = value; }
    uint32_t get_leftover_data(Http2Enums::SourceId source_id) { return leftover_data[source_id]; }
    void set_leftover_data(uint32_t value, Http2Enums::SourceId source_id)
        { leftover_data[source_id] = value; }
};

#endif

