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
#include "http2_hpack.h"
#include "http2_hpack_int_decode.h"
#include "http2_hpack_string_decode.h"
#include "http2_settings_frame.h"

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

    friend class Http2Frame;
    friend class Http2HeadersFrame;
    friend class Http2Hpack;
    friend class Http2Inspect;
    friend class Http2RequestLine;
    friend class Http2SettingsFrame;
    friend class Http2StartLine;
    friend class Http2StatusLine;
    friend class Http2Stream;
    friend class Http2StreamSplitter;
    friend const snort::StreamBuffer implement_reassemble(Http2FlowData*, unsigned, unsigned,
        const uint8_t*, unsigned, uint32_t, HttpCommon::SourceId);
    friend snort::StreamSplitter::Status implement_scan(Http2FlowData*, const uint8_t*, uint32_t,
        uint32_t*, HttpCommon::SourceId);

    size_t size_of() override
    { return sizeof(*this); }

protected:
    // 0 element refers to client frame, 1 element refers to server frame

    // Reassemble() data to eval()
    uint8_t* frame_header[2] = { nullptr, nullptr };
    uint32_t frame_header_size[2] = { 0, 0 };
    uint8_t* frame_data[2] = { nullptr, nullptr };
    uint32_t frame_data_size[2] = { 0, 0 };

    // Used in eval()
    bool frame_in_detection = false;
    Http2ConnectionSettings connection_settings[2];
    Http2HpackDecoder hpack_decoder[2];
    class Http2Stream* stream;

    // Internal to scan()
    bool preface[2] = { true, false };
    bool continuation_expected[2] = { false, false };
    uint8_t scan_frame_header[2][Http2Enums::FRAME_HEADER_LENGTH];
    uint32_t scan_remaining_frame_octets[2] = { 0, 0 };
    uint32_t scan_octets_seen[2] = { 0, 0 };
    uint32_t leftover_data[2] = { 0, 0 };

    // Scan signals to reassemble()
    bool payload_discard[2] = { false, false };
    uint32_t num_frame_headers[2] = { 0, 0 };
    uint32_t total_bytes_in_split[2] = { 0, 0 };
    uint32_t octets_before_first_header[2] = { 0, 0 };

    // Used by scan, reassemble and eval to communicate
    uint8_t frame_type[2] = { Http2Enums::FT__NONE, Http2Enums::FT__NONE };
    
    // Internal to reassemble()
    uint32_t frame_header_offset[2] = { 0, 0 };
    uint32_t frame_data_offset[2] = { 0, 0 };
    uint32_t remaining_frame_octets[2] = { 0, 0 };
    uint8_t padding_octets_in_frame[2] = { 0, 0 };
    bool get_padding_len[2] = { false, false };

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

