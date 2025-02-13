//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_window_update_frame.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_window_update_frame.h"

#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_enum.h"
#include "http2_flow_data.h"

using namespace HttpCommon;
using namespace Http2Enums;

Http2WindowUpdateFrame::Http2WindowUpdateFrame(const uint8_t* header_buffer, const uint32_t header_len,
    const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
    HttpCommon::SourceId src_id, Http2Stream* stream_) : Http2Frame(header_buffer, header_len,
    data_buffer, data_len, ssn_data, src_id, stream_)
{
    if (data.length() != 4)
    {
        session_data->events[source_id]->create_event(EVENT_INVALID_WINDOW_UPDATE_FRAME);
        *session_data->infractions[source_id] += INF_INVALID_WINDOW_UPDATE_FRAME;
    }
    else
    {
        static const uint32_t CLEAR_FIRST_BIT_MASK = 0x7fffffff;
        const uint32_t increment = (data.start()[0] << 24 | data.start()[1] << 16 |
            data.start()[2] << 8 | data.start()[3]) & CLEAR_FIRST_BIT_MASK;
        if (increment == 0)
        {
            session_data->events[source_id]->create_event(EVENT_WINDOW_UPDATE_FRAME_ZERO_INCREMENT);
            *session_data->infractions[source_id] += INF_WINDOW_UPDATE_FRAME_ZERO_INCREMENT;
        }
    }
}

bool Http2WindowUpdateFrame::valid_sequence(Http2Enums::StreamState)
{
    //FIXIT-E Not valid on streams in idle state; add check once we track completed streams
    return true;
}

#ifdef REG_TEST
void Http2WindowUpdateFrame::print_frame(FILE* output)
{
    fprintf(output, "window_update frame\n");
    Http2Frame::print_frame(output);
}
#endif
