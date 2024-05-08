//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_push_promise_frame.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_PUSH_PROMISE_FRAME_H
#define HTTP2_PUSH_PROMISE_FRAME_H

#include "helpers/event_gen.h"
#include "helpers/infractions.h"
#include "service_inspectors/http_inspect/http_common.h"

#include "http2_enum.h"
#include "http2_frame.h"
#include "http2_headers_frame_with_startline.h"

class Field;
class Http2Frame;
class Http2Stream;
class HttpFlowData;

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;
using Http2EventGen = EventGen<Http2Enums::EVENT__MAX_VALUE, Http2Enums::EVENT__NONE,
    Http2Enums::HTTP2_GID>;

class Http2PushPromiseFrame : public Http2HeadersFrameWithStartline
{
public:
    bool valid_sequence(Http2Enums::StreamState state) override;
    void analyze_http1(snort::Packet*) override;
    void update_stream_state() override;
    static uint32_t get_promised_stream_id(Http2EventGen* const events,
        Http2Infractions* const infractions, const uint8_t* data_buffer, uint32_t data_len);

    friend Http2Frame* Http2Frame::new_frame(const uint8_t*, const uint32_t, const uint8_t*,
        const uint32_t, Http2FlowData*, HttpCommon::SourceId, Http2Stream* stream);

#ifdef REG_TEST
    void print_frame(FILE* output) override;
#endif

private:
    Http2PushPromiseFrame(const uint8_t* header_buffer, const uint32_t header_len,
        const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
        HttpCommon::SourceId src_id, Http2Stream* stream);
    uint8_t get_flags_mask() const override;

    bool in_error_state() const override;

    static const int32_t PROMISED_ID_LENGTH = 4;
};
#endif
