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

// http2_flow_data_test.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_FLOW_DATA_TEST_H
#define HTTP2_FLOW_DATA_TEST_H

#include "service_inspectors/http_inspect/http_common.h"
//#include "service_inspectors/http2_inspect/http2_enum.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "service_inspectors/http2_inspect/http2_module.h"

// Stubs whose sole purpose is to make the test code link
snort::FlowData::FlowData(unsigned u, Inspector* ph) : next(nullptr), prev(nullptr), handler(ph), id(u) {}
snort::FlowData::~FlowData() = default;
unsigned snort::FlowData::flow_data_id = 0;
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

class Http2FlowDataTest : public Http2FlowData
{
public:
    bool get_preface(HttpCommon::SourceId source_id) { return preface[source_id]; }
    void set_preface(bool value, HttpCommon::SourceId source_id) { preface[source_id] = value; }
    bool get_num_frame_headers(HttpCommon::SourceId source_id) { return num_frame_headers[source_id]; }
    void set_num_frame_headers(bool value, HttpCommon::SourceId source_id)
        { num_frame_headers[source_id] = value; }
    uint8_t* get_frame_header(HttpCommon::SourceId source_id) { return frame_header[source_id]; }
    void set_frame_header(uint8_t* value, uint32_t length, HttpCommon::SourceId source_id)
        { frame_header[source_id] = value; frame_header_size[source_id] = length; }
    uint8_t* get_scan_frame_header(HttpCommon::SourceId source_id)
        { return scan_frame_header[source_id]; }
    uint8_t* get_frame_data(HttpCommon::SourceId source_id) { return frame_data[source_id]; }
    void set_frame_data(uint8_t* value, HttpCommon::SourceId source_id)
        { frame_data[source_id] = value; }
    uint32_t get_frame_data_size(HttpCommon::SourceId source_id)
        { return frame_data_offset[source_id]; }
    void set_frame_data_size(uint32_t value, HttpCommon::SourceId source_id)
        { frame_data_size[source_id] = value; }
    uint32_t get_leftover_data(HttpCommon::SourceId source_id) { return leftover_data[source_id]; }
    void set_leftover_data(uint32_t value, HttpCommon::SourceId source_id)
        { leftover_data[source_id] = value; }
    void set_total_bytes_in_split(uint32_t value, HttpCommon::SourceId source_id)
        { total_bytes_in_split[source_id] = value; }
    void set_octets_before_first_header(uint32_t value, HttpCommon::SourceId source_id)
        { octets_before_first_header[source_id] = value; }
    void cleanup()
    {
        for (int k = 0; k < 2; k++)
        {
            delete[] frame_header[k];
            delete[] frame_data[k];
        }
    }
};

#endif

