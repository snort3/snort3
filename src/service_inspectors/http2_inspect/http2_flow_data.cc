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
// http2_flow_data.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_flow_data.h"

#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_enum.h"
#include "http2_frame.h"
#include "http2_module.h"
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
    FlowData(inspector_id),
    flow(flow_),
    hi((HttpInspect*)(flow->assistant_gadget)),
    hpack_decoder { Http2HpackDecoder(this, SRC_CLIENT, events[SRC_CLIENT],
                        infractions[SRC_CLIENT]),
                    Http2HpackDecoder(this, SRC_SERVER, events[SRC_SERVER],
                        infractions[SRC_SERVER]) }
{
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
        delete hi_ss[k];
        delete[] frame_data[k];
        delete[] frame_header[k];
    }
}

HttpFlowData* Http2FlowData::get_hi_flow_data() const
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

HttpMsgSection* Http2FlowData::get_hi_msg_section() const
{
    Http2Stream* stream = get_hi_stream();
    if (stream == nullptr)
        return nullptr;
    return stream->get_hi_msg_section();
}

void Http2FlowData::set_hi_msg_section(HttpMsgSection* section)
{
    assert(stream_in_hi != Http2Enums::NO_STREAM_ID);
    Http2Stream* stream = get_hi_stream();
    stream->set_hi_msg_section(section);
}

class Http2Stream* Http2FlowData::find_stream(uint32_t key) const
{
    for (const StreamInfo& stream_info : streams)
    {
        if (stream_info.id == key)
            return stream_info.stream;
    }

    return nullptr;
}

class Http2Stream* Http2FlowData::get_stream(uint32_t key)
{
    class Http2Stream* stream = find_stream(key);
    if (!stream)
    {
        stream = new Http2Stream(key, this);
        streams.emplace_front(key, stream);
    }
    return stream;
}

class Http2Stream* Http2FlowData::get_hi_stream() const
{
    return find_stream(stream_in_hi);
}

class Http2Stream* Http2FlowData::get_current_stream(const HttpCommon::SourceId source_id)
{
    return get_stream(current_stream[source_id]);
}

uint32_t Http2FlowData::get_current_stream_id(const HttpCommon::SourceId source_id)
{
    return current_stream[source_id];
}

void Http2FlowData::allocate_hi_memory()
{
    update_allocations(HttpFlowData::get_memory_usage_estimate());
}

void Http2FlowData::deallocate_hi_memory()
{
    update_deallocations(HttpFlowData::get_memory_usage_estimate());
}
