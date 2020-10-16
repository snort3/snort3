//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// http2_push_promise_frame.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_push_promise_frame.h"

#include "http2_flow_data.h"
#include "http2_stream.h"
#include "http2_utils.h"

using namespace HttpCommon;
using namespace Http2Enums;

Http2PushPromiseFrame::Http2PushPromiseFrame(const uint8_t* header_buffer,
    const uint32_t header_len, const uint8_t* data_buffer, const uint32_t data_len,
    Http2FlowData* session_data_, HttpCommon::SourceId source_id_, Http2Stream* stream_) :
    Http2Frame(header_buffer, header_len, data_buffer, data_len, session_data_, source_id_, stream_)
{
    // If this was a short frame, it's being processed by the stream that sent it. We've already
    // alerted
    if (data_len < PROMISED_ID_LENGTH)
        return;

    // Server-initiated streams must be even
    if (source_id == SRC_SERVER and stream->get_stream_id() % 2 != 0)
    {
        *session_data->infractions[source_id] += INF_INVALID_STREAM_ID;
        session_data->events[source_id]->create_event(EVENT_INVALID_STREAM_ID);
    }

    if (session_data->get_recipient_connection_settings(source_id)->get_param(ENABLE_PUSH) == 0)
    {
        session_data->events[source_id]->create_event(EVENT_PUSH_WHEN_PROHIBITED);
        *session_data->infractions[source_id] += INF_PUSH_WHEN_PROHIBITED;
    }

    // Push_promise frames only define the padded and end_headers flags
    if (get_flags() & ~PADDED & ~END_HEADERS)
    {
        session_data->events[source_id]->create_event(EVENT_INVALID_FLAG);
        *session_data->infractions[source_id] += INF_INVALID_FLAG;
    }
}

bool Http2PushPromiseFrame::valid_sequence(Http2Enums::StreamState)
{
    if (data.length() < PROMISED_ID_LENGTH)
        return false;

    if (source_id == SRC_CLIENT)
    {
        *session_data->infractions[source_id] += INF_C2S_PUSH;
        session_data->events[source_id]->create_event(EVENT_C2S_PUSH);
        return false;
    }

    // Promised stream must not be already in use
    if (stream->get_state(SRC_CLIENT) != STREAM_EXPECT_HEADERS or
        stream->get_state(SRC_SERVER) != STREAM_EXPECT_HEADERS)
    {
        *session_data->infractions[source_id] += INF_INVALID_PROMISED_STREAM;
        session_data->events[source_id]->create_event(EVENT_INVALID_PROMISED_STREAM);
        return false;
    }

    // Alert but continue processing if invalid sequence on stream push_promise was sent on
    Http2Stream* const stream_sent_on = session_data->get_current_stream(source_id);
    if (stream_sent_on->get_state(SRC_CLIENT) == STREAM_EXPECT_HEADERS or
        stream_sent_on->get_state(SRC_SERVER) >= STREAM_COMPLETE)
    {
        *session_data->infractions[source_id] += INF_BAD_PUSH_SEQUENCE;
        session_data->events[source_id]->create_event(EVENT_BAD_PUSH_SEQUENCE);
    }
    return true;
}

void Http2PushPromiseFrame::update_stream_state()
{
    switch (stream->get_state(source_id))
    {
        case STREAM_EXPECT_HEADERS:
            stream->set_state(SRC_CLIENT, STREAM_COMPLETE);
            break;
        default:
            //only STREAM_EXPECT_HEADERS is valid so should never get here
            assert(false);
            stream->set_state(source_id, STREAM_ERROR);
    }
}

uint32_t Http2PushPromiseFrame::get_promised_stream_id(Http2EventGen* const events,
    Http2Infractions* const infractions, const uint8_t* data_buffer, uint32_t data_len)
{
    if (data_len < PROMISED_ID_LENGTH)
    {
        events->create_event(EVENT_INVALID_PUSH_FRAME);
        *infractions += INF_PUSH_FRAME_TOO_SHORT;
        return NO_STREAM_ID;
    }

    // the first four bytes of the push_promise frame are the pushed stream ID
    return get_stream_id_from_buffer(data_buffer);
}

#ifdef REG_TEST
void Http2PushPromiseFrame::print_frame(FILE* output)
{
    fprintf(output, "Push_Promise frame\n");
    Http2Frame::print_frame(output);
}
#endif
