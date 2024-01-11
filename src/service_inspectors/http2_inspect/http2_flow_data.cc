//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_flow_data.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_flow_data.h"

#include "main/snort_types.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_enum.h"
#include "http2_frame.h"
#include "http2_module.h"
#include "http2_push_promise_frame.h"
#include "http2_start_line.h"
#include "http2_stream.h"

using namespace snort;
using namespace Http2Enums;
using namespace HttpCommon;

unsigned Http2FlowData::inspector_id = 0;

#ifdef REG_TEST
uint64_t Http2FlowData::instance_count = 0;
#endif

Http2FlowData::Http2FlowData(Flow* flow_) :
    FlowData(inspector_id,(Inspector*)(flow_->assistant_gadget)),
    flow(flow_),
    hi((HttpInspect*)(flow->assistant_gadget)),
    hpack_decoder { Http2HpackDecoder(this, SRC_CLIENT, events[SRC_CLIENT],
                        infractions[SRC_CLIENT]),
                    Http2HpackDecoder(this, SRC_SERVER, events[SRC_SERVER],
                        infractions[SRC_SERVER]) },
    data_cutter { Http2DataCutter(this, SRC_CLIENT), Http2DataCutter(this, SRC_SERVER) }
{
    static Http2FlowStreamIntf h2_stream;
    if (hi != nullptr)
    {
        hi_ss[SRC_CLIENT] = hi->get_splitter(true);
        hi_ss[SRC_SERVER] = hi->get_splitter(false);
    }

#ifdef REG_TEST
    seq_num = ++instance_count;
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2) &&
        !HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
    {
        printf("HTTP/2 Flow Data construct %" PRIu64 "\n", seq_num);
        fflush(nullptr);
    }
#endif
    Http2Module::increment_peg_counts(PEG_CONCURRENT_SESSIONS);
    if (Http2Module::get_peg_counts(PEG_MAX_CONCURRENT_SESSIONS) <
        Http2Module::get_peg_counts(PEG_CONCURRENT_SESSIONS))
        Http2Module::increment_peg_counts(PEG_MAX_CONCURRENT_SESSIONS);

    flow->stream_intf = &h2_stream;
}

Http2FlowData::~Http2FlowData()
{
#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2) &&
        !HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
    {
        printf("HTTP/2 Flow Data destruct %" PRIu64 "\n", seq_num);
        fflush(nullptr);
    }
#endif
    if (Http2Module::get_peg_counts(PEG_CONCURRENT_SESSIONS) > 0)
        Http2Module::decrement_peg_counts(PEG_CONCURRENT_SESSIONS);

    for (int k=0; k <= 1; k++)
    {
        delete infractions[k];
        delete events[k];
        hi_ss[k]->go_away();
        delete[] frame_data[k];
    }

    flow->stream_intf = nullptr;
}

HttpFlowData* Http2FlowData::get_hi_flow_data()
{
    assert(stream_in_hi != Http2Enums::NO_STREAM_ID);
    Http2Stream* stream = get_hi_stream();
    return stream->get_hi_flow_data();
}

void Http2FlowData::set_hi_flow_data(HttpFlowData* flow)
{
    assert(stream_in_hi != Http2Enums::NO_STREAM_ID);
    Http2Stream* stream = get_hi_stream();
    stream->set_hi_flow_data(flow);
}

Http2Stream* Http2FlowData::find_stream(const uint32_t key)
{
    auto it = std::find_if(streams.begin(), streams.end(),
        [key](const Http2Stream &stream){ return stream.get_stream_id() == key; });
    return (it != streams.end()) ? &(*it) : nullptr;
}

Http2Stream* Http2FlowData::get_processing_stream(const SourceId source_id, uint32_t concurrent_streams_limit)
{
    const uint32_t key = processing_stream_id;
    class Http2Stream* stream = find_stream(key);
    if (!stream)
    {
        if (concurrent_streams >= concurrent_streams_limit)
        {
            *infractions[source_id] += INF_TOO_MANY_STREAMS;
            events[source_id]->create_event(EVENT_TOO_MANY_STREAMS);
            events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
            Http2Module::increment_peg_counts(PEG_FLOWS_OVER_STREAM_LIMIT);
            abort_flow[SRC_CLIENT] = true;
            abort_flow[SRC_SERVER] = true;
            return nullptr;
        }

        // Verify stream id is bigger than all previous streams initiated by same side
        if (key != 0)
        {
            const bool non_housekeeping_frame = frame_type[source_id] == FT_HEADERS ||
                                                frame_type[source_id] == FT_DATA ||
                                                frame_type[source_id] == FT_PUSH_PROMISE;
            if (non_housekeeping_frame)
            {
                // If we see both sides of traffic, odd stream id should be initiated by client,
                // even by server. If we can't see one side, can't guarantee order
                const bool is_on_expected_side = (key % 2 != 0 && source_id == SRC_CLIENT) ||
                                                 (key % 2 == 0 && source_id == SRC_SERVER);
                if (is_on_expected_side)
                {
                    if (key <= max_stream_id[source_id])
                    {
                        *infractions[source_id] += INF_INVALID_STREAM_ID;
                        events[source_id]->create_event(EVENT_INVALID_STREAM_ID);
                        return nullptr;
                    }
                    else
                        max_stream_id[source_id] = key;
                }
            }
            else // housekeeping frame
            {
                // Delete stream after this frame is evaluated.
                // Prevents recreating and keeping already completed streams for
                // housekeeping frames
                delete_stream = true;
            }
        }

        // Allocate new stream
        streams.emplace_front(key, this);
        stream = &streams.front();

        // stream 0 does not count against stream limit
        if (key > 0)
        {
            concurrent_streams += 1;
            if (concurrent_streams > Http2Module::get_peg_counts(PEG_MAX_CONCURRENT_STREAMS))
                Http2Module::increment_peg_counts(PEG_MAX_CONCURRENT_STREAMS);
        }
    }
    return stream;
}

void Http2FlowData::delete_processing_stream()
{
    std::list<Http2Stream>::iterator it;

    for (it = streams.begin(); it != streams.end(); ++it)
    {
        if (it->get_stream_id() == processing_stream_id)
        {
            streams.erase(it);
            delete_stream = false;
            assert(concurrent_streams > 0);
            concurrent_streams -= 1;
            return;
        }
    }
    assert(false);
}

Http2Stream* Http2FlowData::get_hi_stream()
{
    return find_stream(stream_in_hi);
}

Http2Stream* Http2FlowData::find_current_stream(const SourceId source_id)
{
    return find_stream(current_stream[source_id]);
}

Http2Stream* Http2FlowData::find_processing_stream()
{
    return find_stream(get_processing_stream_id());
}

uint32_t Http2FlowData::get_processing_stream_id() const
{
    return processing_stream_id;
}

// processing stream is the current stream except for push promise frames with properly formatted
// promised stream IDs
void Http2FlowData::set_processing_stream_id(const SourceId source_id)
{
    assert(processing_stream_id == NO_STREAM_ID);
    if (frame_type[source_id] == FT_PUSH_PROMISE)
        processing_stream_id = Http2PushPromiseFrame::get_promised_stream_id(
            events[source_id], infractions[source_id], frame_data[source_id],
            frame_data_size[source_id]);
    if (processing_stream_id == NO_STREAM_ID)
        processing_stream_id = current_stream[source_id];
}

uint32_t Http2FlowData::get_current_stream_id(const SourceId source_id) const
{
    return current_stream[source_id];
}

bool Http2FlowData::is_mid_frame() const
{
    return (header_octets_seen[SRC_SERVER] != 0) || (remaining_data_padding[SRC_SERVER] != 0) ||
        continuation_expected[SRC_SERVER];
}

FlowData* Http2FlowStreamIntf::get_stream_flow_data(const Flow* flow)
{
    Http2FlowData* h2i_flow_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    assert(h2i_flow_data);

    return h2i_flow_data->get_hi_flow_data();
}

void Http2FlowStreamIntf::set_stream_flow_data(Flow* flow, FlowData* flow_data)
{
    Http2FlowData* h2i_flow_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    assert(h2i_flow_data);

    h2i_flow_data->set_hi_flow_data((HttpFlowData*)flow_data);
}

void Http2FlowStreamIntf::get_stream_id(const Flow* flow, int64_t& stream_id)
{
    Http2FlowData* h2i_flow_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    assert(h2i_flow_data);

    stream_id = h2i_flow_data->get_processing_stream_id();
}

AppId Http2FlowStreamIntf::get_appid_from_stream(const Flow* flow)
{
#ifdef NDEBUG
    UNUSED(flow);
#else
    Http2FlowData* h2i_flow_data = (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    assert(h2i_flow_data);
#endif

    return APP_ID_HTTP2;
}

void* Http2FlowStreamIntf::get_hi_msg_section(const Flow* flow)
{
    const Http2FlowData* const h2i_flow_data =
        (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    HttpMsgSection* current_section = nullptr;
    if (h2i_flow_data)
        current_section = h2i_flow_data->get_hi_msg_section();
    return current_section;
}

void Http2FlowStreamIntf::set_hi_msg_section(Flow* flow, void* section)
{
    Http2FlowData* h2i_flow_data =
        (Http2FlowData*)flow->get_flow_data(Http2FlowData::inspector_id);
    if (h2i_flow_data)
        h2i_flow_data->set_hi_msg_section((HttpMsgSection*)section);

}
