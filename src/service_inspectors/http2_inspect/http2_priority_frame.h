//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_priority_frame.h author Adrian Mamolea <admamole@cisco.com>

#ifndef HTTP2_PRIORITY_FRAME_H
#define HTTP2_PRIORITY_FRAME_H

#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_frame.h"

class Http2PriorityFrame : public Http2Frame
{
public:
    friend Http2Frame* Http2Frame::new_frame(const uint8_t*, const uint32_t, const uint8_t*,
        const uint32_t, Http2FlowData*, HttpCommon::SourceId, const Http2ParaList* params, Http2Stream* stream);
    bool is_detection_required() const override { return false; }

private:
    Http2PriorityFrame(const uint8_t* header_buffer, const uint32_t header_len,
        const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
        HttpCommon::SourceId src_id, Http2Stream* _stream) :
        Http2Frame(header_buffer, header_len, data_buffer, data_len, ssn_data, src_id, _stream)
    {
        if (get_stream_id() == 0)
        {
            *session_data->infractions[source_id] += Http2Enums::INF_BAD_PRIORITY_FRAME_STREAM_ID;
            session_data->events[source_id]->create_event(Http2Enums::EVENT_INVALID_PRIORITY_FRAME);
        }
        if (data.length() != 5)
        {
            *session_data->infractions[source_id] += Http2Enums::INF_BAD_PRIORITY_FRAME_LENGTH;
            session_data->events[source_id]->create_event(Http2Enums::EVENT_INVALID_PRIORITY_FRAME);
        }
    }
};
#endif

