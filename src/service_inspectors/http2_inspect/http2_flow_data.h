//--------------------------------------------------------------------------
// Copyright (C) 2018-2020 Cisco and/or its affiliates. All rights reserved.
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
#include "http2_stream.h"

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;

using Http2EventGen = EventGen<Http2Enums::EVENT__MAX_VALUE, Http2Enums::EVENT__NONE,
    Http2Enums::HTTP2_GID>;

class HttpFlowData;
class HttpMsgSection;
class HttpInspect;
class HttpStreamSplitter;

class Http2FlowData : public snort::FlowData
{
public:
    Http2FlowData(snort::Flow* flow_);
    ~Http2FlowData() override;
    static unsigned inspector_id;
    static void init() { inspector_id = snort::FlowData::create_flow_data_id(); }

    // Used by http_inspect to store its stuff
    HttpFlowData* get_hi_flow_data() const;
    void set_hi_flow_data(HttpFlowData* flow);
    HttpMsgSection* get_hi_msg_section() const;
    void set_hi_msg_section(HttpMsgSection* section);

    friend class Http2Frame;
    friend class Http2DataFrame;
    friend class Http2DataCutter;
    friend class Http2HeadersFrame;
    friend class Http2Hpack;
    friend class Http2Inspect;
    friend class Http2RequestLine;
    friend class Http2SettingsFrame;
    friend class Http2StartLine;
    friend class Http2StatusLine;
    friend class Http2Stream;
    friend class Http2StreamSplitter;
    friend void finish_msg_body(Http2FlowData* session_data, HttpCommon::SourceId source_id);

    size_t size_of() override
    { return sizeof(*this); }

    // Stream access
    class StreamInfo
    {
public:
        const uint32_t id;
        class Http2Stream* stream;

        StreamInfo(uint32_t _id, class Http2Stream* ptr) : id(_id), stream(ptr) { assert(ptr); }
        ~StreamInfo() { delete stream; }
    };
    class Http2Stream* get_current_stream(const HttpCommon::SourceId source_id);
    uint32_t get_current_stream_id(const HttpCommon::SourceId source_id);

    Http2HpackDecoder* get_hpack_decoder(const HttpCommon::SourceId source_id)
    { return &hpack_decoder[source_id]; }
    Http2ConnectionSettings* get_connection_settings(const HttpCommon::SourceId source_id)
    { return &connection_settings[source_id]; }

protected:
    snort::Flow* flow;
    HttpInspect* const hi;
    HttpStreamSplitter* hi_ss[2] = { nullptr, nullptr };

    // 0 element refers to client frame, 1 element refers to server frame

    // There is currently one infraction and one event object per flow per direction. This may
    // change in the future.
    Http2Infractions* const infractions[2] = { new Http2Infractions, new Http2Infractions };
    Http2EventGen* const events[2] = { new Http2EventGen, new Http2EventGen };

    // Stream ID of the frame currently being read in and processed
    uint32_t current_stream[2] = { Http2Enums::NO_STREAM_ID, Http2Enums::NO_STREAM_ID };
    // At any given time there may be different streams going in each direction. But only one of
    // them is the stream that http_inspect is actually processing at the moment.
    uint32_t stream_in_hi = Http2Enums::NO_STREAM_ID;

    // Reassemble() data to eval()
    uint8_t* frame_header[2] = { nullptr, nullptr };
    uint32_t frame_header_size[2] = { 0, 0 };
    uint8_t* frame_data[2] = { nullptr, nullptr };
    uint32_t frame_data_size[2] = { 0, 0 };

    // Used in eval()
    bool frame_in_detection = false;
    Http2ConnectionSettings connection_settings[2];
    Http2HpackDecoder hpack_decoder[2];
    std::list<class StreamInfo> streams;
    uint32_t concurrent_files = 0;

    // Internal to scan()
    bool preface[2] = { true, false };
    bool continuation_expected[2] = { false, false };
    uint8_t scan_frame_header[2][Http2Enums::FRAME_HEADER_LENGTH];
    uint32_t scan_remaining_frame_octets[2] = { 0, 0 };
    uint32_t scan_octets_seen[2] = { 0, 0 };
    bool mid_data_frame[2] = { false, false }; //set for data frame with multiple flushes
    bool data_processing[2] = { false, false };

    // Scan signals to reassemble()
    bool payload_discard[2] = { false, false };
    uint32_t num_frame_headers[2] = { 0, 0 };
    uint32_t total_bytes_in_split[2] = { 0, 0 };
    bool use_leftover_hdr[2] = { false, false };
    uint8_t leftover_hdr[2][Http2Enums::FRAME_HEADER_LENGTH];

    // Used by scan, reassemble
    bool flushing_data[2] = { false, false };

    // Used by scan, reassemble and eval to communicate
    uint8_t frame_type[2] = { Http2Enums::FT__NONE, Http2Enums::FT__NONE };

    // Internal to reassemble()
    uint32_t frame_header_offset[2] = { 0, 0 };
    uint32_t frame_data_offset[2] = { 0, 0 };
    uint32_t remaining_frame_octets[2] = { 0, 0 };
    uint8_t padding_octets_in_frame[2] = { 0, 0 };
    bool get_padding_len[2] = { false, false };

#ifdef REG_TEST
    static uint64_t instance_count;
    uint64_t seq_num;
#endif

private:
    class Http2Stream* get_stream(uint32_t key);
    class Http2Stream* get_hi_stream() const;
    class Http2Stream* find_stream(uint32_t key) const;

    // When H2I allocates http_inspect flows, it bypasses the usual FlowData memory allocation
    // bookkeeping. So H2I needs to update memory allocations and deallocations itself.
    void allocate_hi_memory();
    void deallocate_hi_memory();
};

#endif

