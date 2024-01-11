//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_rst_stream_frame.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_rst_stream_frame.h"

#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_enum.h"
#include "http2_flow_data.h"

using namespace HttpCommon;
using namespace Http2Enums;

Http2RstStreamFrame::Http2RstStreamFrame(const uint8_t* header_buffer, const uint32_t header_len,
    const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* ssn_data,
    HttpCommon::SourceId src_id, Http2Stream* stream_) : Http2Frame(header_buffer, header_len,
    data_buffer, data_len, ssn_data, src_id, stream_)
{
    if ((get_stream_id() == 0) or (data.length() != 4))
    {
        session_data->events[source_id]->create_event(EVENT_INVALID_RST_STREAM_FRAME);
        *session_data->infractions[source_id] += INF_INVALID_RST_STREAM_FRAME;
    }
}

bool Http2RstStreamFrame::valid_sequence(Http2Enums::StreamState)
{
    // FIXIT-E uncomment once we track completed streams
    /*
    if (stream->get_state(SRC_CLIENT) == STREAM_EXPECT_HEADERS and
        stream->get_state(SRC_SERVER) == STREAM_EXPECT_HEADERS)
    {
        session_data->events[source_id]->create_event(EVENT_BAD_RST_STREAM_SEQUENCE);
        *session_data->infractions[source_id] += INF_BAD_RST_STREAM_SEQUENCE;
    }
    */
    return true;
}

void Http2RstStreamFrame::update_stream_state()
{
    if (stream->get_state(source_id) < STREAM_COMPLETE)
        stream->set_state(source_id, STREAM_COMPLETE);
}

#ifdef REG_TEST
void Http2RstStreamFrame::print_frame(FILE* output)
{
    fprintf(output, "rst_stream frame\n");
    Http2Frame::print_frame(output);
}
#endif
