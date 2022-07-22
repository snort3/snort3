//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// http2_stream.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_enum.h"
#include "http2_stream.h"

#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"

#include "http2_data_cutter.h"
#include "http2_flow_data.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

Http2Stream::Http2Stream(uint32_t stream_id_, Http2FlowData* session_data_) :
    stream_id(stream_id_),
    session_data(session_data_)
{
}

Http2Stream::~Http2Stream()
{
    delete current_frame;
    delete hi_flow_data;
}

void Http2Stream::eval_frame(const uint8_t* header_buffer, uint32_t header_len,
    const uint8_t* data_buffer, uint32_t data_len, SourceId source_id, Packet* p)
{
    assert(current_frame == nullptr);
    current_frame = Http2Frame::new_frame(header_buffer, header_len, data_buffer,
        data_len, session_data, source_id, this);
    if (!session_data->abort_flow[source_id] && (get_state(source_id) != STREAM_ERROR))
    {
        if (current_frame->valid_sequence(state[source_id]))
        {
            current_frame->analyze_http1(p);
            current_frame->update_stream_state();
        }
        else
        {
            set_state(source_id, STREAM_ERROR);
        }
    }
}

// check if stream is completed, do cleanup if it is
void Http2Stream::check_and_cleanup_completed()
{
    if ((state[SRC_CLIENT] >= STREAM_COMPLETE) && (state[SRC_SERVER] >= STREAM_COMPLETE))
    {
        if (hi_flow_data != nullptr)
        {
            delete hi_flow_data;
            hi_flow_data = nullptr;
        }
        session_data->delete_stream = true;
    }
}

void Http2Stream::clear_frame(Packet* p)
{
    assert(current_frame != nullptr);
    current_frame->clear(p);
    delete current_frame;
    current_frame = nullptr;

    check_and_cleanup_completed();
}

void Http2Stream::set_state(HttpCommon::SourceId source_id, StreamState new_state)
{
    assert((STREAM_EXPECT_HEADERS <= new_state) && (new_state <= STREAM_ERROR));
    assert(state[source_id] < new_state);
    assert((new_state < STREAM_EXPECT_BODY) || (new_state > STREAM_BODY) ||
        (get_hi_flow_data() != nullptr));
    state[source_id] = new_state;
}

void Http2Stream::set_hi_flow_data(HttpFlowData* flow_data)
{
    assert(hi_flow_data == nullptr);
    hi_flow_data = flow_data;
}

const Field& Http2Stream::get_buf(unsigned id)
{
    if (current_frame != nullptr)
        return current_frame->get_buf(id);
    return Field::FIELD_NULL;
}

#ifdef REG_TEST
void Http2Stream::print_frame(FILE* output)
{
    if (current_frame != nullptr)
        current_frame->print_frame(output);
}
#endif

bool Http2Stream::is_open(HttpCommon::SourceId source_id)
{
    return (state[source_id] == STREAM_EXPECT_BODY) || (state[source_id] == STREAM_BODY);
}

// Caller must set session_data->stream_in_hi before calling this
void Http2Stream::finish_msg_body(HttpCommon::SourceId source_id, bool expect_trailers,
    bool clear_partial_buffer)
{
    uint32_t http_flush_offset = 0;
    const H2BodyState body_state = expect_trailers ?
        H2_BODY_COMPLETE_EXPECT_TRAILERS : H2_BODY_COMPLETE;
    get_hi_flow_data()->finish_h2_body(source_id, body_state, clear_partial_buffer);
    if (clear_partial_buffer)
    {
        const StreamSplitter::Status scan_result = session_data->hi_ss[source_id]->scan(
            session_data->flow, nullptr, 0, &http_flush_offset);
        assert(scan_result == StreamSplitter::FLUSH);
        UNUSED(scan_result);
    }
}
