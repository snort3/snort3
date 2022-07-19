//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
// http2_goaway_frame.cc author Adrian Mamolea <admamole@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_goaway_frame.h"

#include "http2_enum.h"
#include "http2_frame.h"

using namespace Http2Enums;

Http2GoAwayFrame::Http2GoAwayFrame(const uint8_t* header_buffer, const uint32_t header_len,
    const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
    HttpCommon::SourceId src_id, Http2Stream* _stream) :
    Http2Frame(header_buffer, header_len, data_buffer, data_len, ssn_data, src_id, _stream)
{
    if (get_stream_id() != 0)
    {
        session_data->events[source_id]->create_event(EVENT_INVALID_GOAWAY_FRAME);
        *session_data->infractions[source_id] += INF_BAD_GOAWAY_FRAME_STREAM_ID;
    }
    if (data.length() < 8)
    {
        session_data->events[source_id]->create_event(EVENT_INVALID_GOAWAY_FRAME);
        *session_data->infractions[source_id] += INF_BAD_GOAWAY_FRAME_LENGTH;
    }
    else if (data.start()[0] & 0x80)
    {
        session_data->events[source_id]->create_event(EVENT_INVALID_GOAWAY_FRAME);
        *session_data->infractions[source_id] += INF_BAD_GOAWAY_FRAME_R_BIT;
    }
}

