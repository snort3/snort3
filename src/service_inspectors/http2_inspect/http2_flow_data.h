//--------------------------------------------------------------------------
// Copyright (C) 2018-2022 Cisco and/or its affiliates. All rights reserved.
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

#include <queue>
#include <vector>

#include "main/snort_types.h"
#include "utils/event_gen.h"
#include "utils/infractions.h"
#include "flow/flow.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "stream/stream_splitter.h"

#include "http2_data_cutter.h"
#include "http2_enum.h"
#include "http2_hpack.h"
#include "http2_hpack_int_decode.h"
#include "http2_hpack_string_decode.h"
#include "http2_settings_frame.h"
#include "http2_stream.h"

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;

using Http2EventGen = EventGen<Http2Enums::EVENT__MAX_VALUE, Http2Enums::EVENT__NONE,
    Http2Enums::HTTP2_GID>;

class HttpFlowData;
class HttpMsgSection;
class HttpInspect;
class HttpStreamSplitter;

class SO_PUBLIC Http2FlowData : public snort::FlowData
{
public:
    Http2FlowData(snort::Flow* flow_);
    ~Http2FlowData() override;
    static unsigned inspector_id;
    static void init() { inspector_id = snort::FlowData::create_flow_data_id(); }

    // Used by http_inspect to store its stuff
    HttpFlowData* get_hi_flow_data() const;
    void set_hi_flow_data(HttpFlowData* flow);
    HttpMsgSection* get_hi_msg_section() const { return hi_msg_section; }
    void set_hi_msg_section(HttpMsgSection* section)
        { assert((hi_msg_section == nullptr) || (section == nullptr)); hi_msg_section = section; }

    friend class Http2Frame;
    friend class Http2DataFrame;
    friend class Http2DataCutter;
    friend class Http2GoAwayFrame;
    friend class Http2HeadersFrame;
    friend class Http2HeadersFrameHeader;
    friend class Http2HeadersFrameTrailer;
    friend class Http2HeadersFrameWithStartline;
    friend class Http2Hpack;
    friend class Http2Inspect;
    friend class Http2PriorityFrame;
    friend class Http2PushPromiseFrame;
    friend class Http2RequestLine;
    friend class Http2RstStreamFrame;
    friend class Http2SettingsFrame;
    friend class Http2StartLine;
    friend class Http2StatusLine;
    friend class Http2Stream;
    friend class Http2StreamSplitter;
    friend class Http2WindowUpdateFrame;
    friend void finish_msg_body(Http2FlowData* session_data, HttpCommon::SourceId source_id);

    Http2Stream* find_current_stream(const HttpCommon::SourceId source_id) const;
    uint32_t get_current_stream_id(const HttpCommon::SourceId source_id) const;
    Http2Stream* get_processing_stream(const HttpCommon::SourceId source_id, uint32_t concurrent_streams_limit);
    Http2Stream* find_processing_stream() const;
    uint32_t get_processing_stream_id() const;
    void set_processing_stream_id(const HttpCommon::SourceId source_id);
    bool is_processing_partial_header() const { return processing_partial_header; }

    Http2HpackDecoder* get_hpack_decoder(const HttpCommon::SourceId source_id)
    { return &hpack_decoder[source_id]; }
    Http2ConnectionSettings* get_my_connection_settings(const HttpCommon::SourceId source_id)
    { return &connection_settings[source_id]; }
    Http2ConnectionSettings* get_remote_connection_settings(const HttpCommon::SourceId source_id)
    { return &connection_settings[1 - source_id]; }

    // Used by payload injection to determine whether we are at a safe place to insert our own
    // frame into the S2C direction of an HTTP/2 flow.
    bool is_mid_frame() const;

    // Used by payload injection to determine whether we should inject S2C settings frame 
    // before injecting payload
    bool was_server_settings_received() const
    { return server_settings_frame_received; }

    void set_server_settings_received()
    { server_settings_frame_received = true; }

#ifdef UNIT_TEST
    void set_mid_frame(bool); // Not implemented outside of unit tests
#endif

protected:
    snort::Flow* flow;
    HttpInspect* const hi;
    HttpStreamSplitter* hi_ss[2] = { nullptr, nullptr };

    // 0 element refers to client frame, 1 element refers to server frame

    // There are currently one infraction and one event object per flow per direction.
    Http2Infractions* const infractions[2] = { new Http2Infractions, new Http2Infractions };
    Http2EventGen* const events[2] = { new Http2EventGen, new Http2EventGen };

    // Stream ID of the frame currently being processed was sent on (i.e. the stream in the frame
    // header). This is set in scan().
    uint32_t current_stream[2] = { Http2Enums::NO_STREAM_ID, Http2Enums::NO_STREAM_ID };
    // Stream ID of the stream responsible for processing the current frame. This will be the same
    // as current_stream except when processing a push_promise frame. This is set in eval() and
    // cleared in clear().
    uint32_t processing_stream_id = Http2Enums::NO_STREAM_ID;
    // At any given time there may be different streams going in each direction. But only one of
    // them is the stream that http_inspect is actually processing at the moment.
    uint32_t stream_in_hi = Http2Enums::NO_STREAM_ID;
    HttpMsgSection* hi_msg_section = nullptr;
    bool server_settings_frame_received = false;
    bool tcp_close[2] = { false, false };

    // Reassemble() data to eval()
    uint8_t lead_frame_header[2][Http2Enums::FRAME_HEADER_LENGTH];
    const uint8_t* frame_data[2] = { nullptr, nullptr };
    uint32_t frame_data_size[2] = { 0, 0 };

    // Used in eval()
    Http2ConnectionSettings connection_settings[2];
    Http2HpackDecoder hpack_decoder[2];
    std::list<Http2Stream*> streams;
    uint32_t concurrent_files = 0;
    uint32_t concurrent_streams = 0;
    uint32_t stream_memory_allocations_tracked = Http2Enums::STREAM_MEMORY_TRACKING_INCREMENT;
    uint32_t max_stream_id[2] = {0, 0};
    bool frame_in_detection = false;
    bool delete_stream = false;

    // Internal to scan()
    bool preface[2] = { true, false };
    uint32_t preface_octets_seen = 0;
    bool continuation_expected[2] = { false, false };
    uint8_t scan_frame_header[2][Http2Enums::FRAME_HEADER_LENGTH];
    uint32_t scan_remaining_frame_octets[2] = { 0, 0 };
    uint32_t header_octets_seen[2] = { 0, 0 };
    uint8_t padding_length[2] = { 0, 0 };
    uint8_t remaining_data_padding[2] = { 0, 0 };
    Http2Enums::ScanState scan_state[2] =
        { Http2Enums::SCAN_FRAME_HEADER, Http2Enums::SCAN_FRAME_HEADER };

    // Used by scan() and reassemble()
    Http2DataCutter data_cutter[2];

    // Scan signals to reassemble()
    uint32_t bytes_scanned[2] = { 0, 0 };
    bool payload_discard[2] = { false, false };

    // Used by scan, reassemble and eval to communicate
    uint8_t frame_type[2] = { Http2Enums::FT__NONE, Http2Enums::FT__NONE };
    bool abort_flow[2] = { false, false };
    bool processing_partial_header = false;
    std::queue<uint32_t> frame_lengths[2];
    uint32_t accumulated_frame_length[2] = { 0, 0 };

    // Internal to reassemble()
    uint32_t frame_header_offset[2] = { 0, 0 };
    uint32_t frame_data_offset[2] = { 0, 0 };
    uint32_t remaining_frame_octets[2] = { 0, 0 };
    uint32_t running_total[2] = { 0, 0 };
    uint8_t remaining_padding_reassemble[2] = { 0, 0 };
    bool read_frame_header[2] = { false, false };
    bool continuation_frame[2] = { false, false };
    bool read_padding_len[2] = { false, false };
    uint8_t* frame_reassemble[2] = { nullptr, nullptr };

#ifdef REG_TEST
    static uint64_t instance_count;
    uint64_t seq_num;
#endif

private:
    Http2Stream* get_hi_stream() const;
    Http2Stream* find_stream(const uint32_t key) const;
    void delete_processing_stream();
};

#endif

