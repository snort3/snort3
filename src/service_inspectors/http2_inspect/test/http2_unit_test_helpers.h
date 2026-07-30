//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// http2_unit_test_helpers.h author Oleksandr Fedorych <ofedoryc@cisco.com>

#ifndef HTTP2_UNIT_TEST_HELPERS_H
#define HTTP2_UNIT_TEST_HELPERS_H

#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "service_inspectors/http2_inspect/http2_stream_splitter.h"

class Http2UnitTestSetup
{
public:
    static bool* get_abort_flow(Http2FlowData* const session_data, HttpCommon::SourceId source_id)
    { return &session_data->abort_flow[source_id]; }

    static uint32_t* get_bytes_scanned(Http2FlowData* const session_data, HttpCommon::SourceId source_id)
    { return &session_data->bytes_scanned[source_id]; }

    static uint32_t* get_current_stream_id(Http2FlowData* const session_data, HttpCommon::SourceId source_id)
    { return &session_data->current_stream[source_id]; }

    static Http2DataCutter* get_data_cutter(Http2FlowData* const session_data, HttpCommon::SourceId source_id)
    { return &session_data->data_cutter[source_id]; }

    static std::queue<uint32_t>* get_frame_lengths(Http2FlowData* const session_data, HttpCommon::SourceId source_id)
    { return &session_data->frame_lengths[source_id]; }

    static uint32_t* get_scan_reamining_frame_octets(Http2FlowData* const session_data, HttpCommon::SourceId source_id)
    { return &session_data->scan_remaining_frame_octets[source_id]; }

    static Http2Enums::ScanState* get_scan_state(Http2FlowData* const session_data, HttpCommon::SourceId source_id)
    { return &session_data->scan_state[source_id]; }

    static std::list<Http2Stream>* get_streams(Http2FlowData* const session_data)
    { return &session_data->streams; }

    static uint32_t& get_frame_bytes_seen(Http2DataCutter& cutter)
    { return cutter.frame_bytes_seen; }

    static snort::StreamSplitter::Status implement_scan(Http2StreamSplitter* splitter, Http2FlowData* session_data,
        const uint8_t* data, uint32_t length, uint32_t* flush_offset, HttpCommon::SourceId source_id,
        snort::Packet* pkt)
    { return splitter->implement_scan(session_data, data, length, flush_offset, source_id, pkt); }

    static const snort::StreamBuffer implement_reassemble(Http2StreamSplitter* splitter, Http2FlowData* session_data,
        unsigned total, unsigned offset, const uint8_t* data, unsigned len, uint32_t flags,
        HttpCommon::SourceId source_id)
    { return splitter->implement_reassemble(session_data, total, offset, data, len, flags, source_id); }
};

#endif
