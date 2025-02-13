//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_frame.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_frame.h"

#include "http2_data_frame.h"
#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_goaway_frame.h"
#include "http2_headers_frame_header.h"
#include "http2_headers_frame_trailer.h"
#include "http2_ping_frame.h"
#include "http2_priority_frame.h"
#include "http2_push_promise_frame.h"
#include "http2_rst_stream_frame.h"
#include "http2_settings_frame.h"
#include "http2_stream.h"
#include "http2_window_update_frame.h"
#include "service_inspectors/http_inspect/http_field.h"

using namespace HttpCommon;
using namespace Http2Enums;
using namespace snort;

Http2Frame::Http2Frame(const uint8_t* header_buffer, const uint32_t header_len,
    const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* session_data,
    SourceId source_id, Http2Stream* stream_) :
    session_data(session_data), source_id(source_id), stream(stream_)
{
    header.set(header_len, header_buffer, true);
    // FIXIT-E want to refactor so that zero-length frames are not a special case
    if (data_buffer != nullptr)
        data.set(data_len, data_buffer, true);
    else
        data.set(0, new uint8_t[0], true);
}

Http2Frame* Http2Frame::new_frame(const uint8_t* header, const uint32_t header_len,
    const uint8_t* data, const uint32_t data_len, Http2FlowData* session_data, SourceId source_id,
    Http2Stream* stream)
{
    Http2Frame* frame = nullptr;

    switch(session_data->frame_type[source_id])
    {
        case FT_HEADERS:
            if (stream->get_state(source_id) == STREAM_EXPECT_HEADERS)
                frame = new Http2HeadersFrameHeader(header, header_len, data, data_len,
                    session_data, source_id, stream);
            else
                frame = new Http2HeadersFrameTrailer(header, header_len, data, data_len,
                    session_data, source_id, stream);
            break;
        case FT_PRIORITY:
            frame = new Http2PriorityFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
            break;
        case FT_SETTINGS:
            frame = new Http2SettingsFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
            break;
        case FT_DATA:
            frame = new Http2DataFrame(header, header_len, data, data_len, session_data, source_id,
                stream);
            break;
        case FT_PUSH_PROMISE:
            frame = new Http2PushPromiseFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
            break;
        case FT_PING:
            frame = new Http2PingFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
            break;
        case FT_GOAWAY:
            frame = new Http2GoAwayFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
            break;
        case FT_RST_STREAM:
            frame = new Http2RstStreamFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
            break;
        case FT_WINDOW_UPDATE:
            frame = new Http2WindowUpdateFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
            break;
        default:
            frame = new Http2Frame(header, header_len, data, data_len, session_data, source_id,
                stream);
    }

    const uint8_t flags = frame->get_flags();
    if (flags != (flags & frame->get_flags_mask()))
    {
        *session_data->infractions[source_id] += INF_INVALID_FLAG;
        session_data->events[source_id]->create_event(EVENT_INVALID_FLAG);
    }

    return frame;
}

const Field& Http2Frame::get_buf(unsigned id)
{
    switch (id)
    {
    case HTTP2_BUFFER_FRAME_HEADER:
        return header;
    case HTTP2_BUFFER_FRAME_DATA:
        return data;
    default:
        return Field::FIELD_NULL;
    }
}

uint8_t Http2Frame::get_flags()
{
    assert(header.length() > 0);
    return header.start()[flags_index];
}

uint32_t Http2Frame::get_stream_id()
{
    if (header.length() <= 0)
        return INVALID_STREAM_ID;

    const uint8_t* header_start = header.start();
    return ((header_start[stream_id_index] & 0x7f) << 24) +
        (header_start[stream_id_index + 1] << 16) +
        (header_start[stream_id_index + 2] << 8) +
        header_start[stream_id_index + 3];
}

#ifdef REG_TEST
void Http2Frame::print_frame(FILE* output)
{
    header.print(output, "Frame Header");
    data.print(output, "Frame Data");
}
#endif

const uint8_t* Http2Frame::get_frame_pdu(uint16_t& length) const
{
    int32_t hlen = header.length();
    if (hlen != FRAME_HEADER_LENGTH)
        return nullptr;

    uint32_t dlen;
    const uint8_t* frame_data = get_frame_data(dlen);
    if (!frame_data or (hlen + dlen > UINT16_MAX))
        return nullptr;

    length = (uint16_t)(hlen + dlen);
    uint8_t* pdu = new uint8_t[length];
    memcpy(pdu, header.start(), hlen);
    if (dlen)
        memcpy(&pdu[hlen], frame_data, dlen);

    pdu[0] = (dlen >> 16) & 0xff;
    pdu[1] = (dlen >> 8) & 0xff;
    pdu[2] = dlen & 0xff;

    return pdu;
}

const uint8_t* Http2Frame::get_frame_data(uint32_t& length) const
{
    int32_t dlen = data.length();
    if (dlen < 0)
        return nullptr;

    length = (uint32_t)dlen;
    return data.start();
}
