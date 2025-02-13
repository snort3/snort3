//--------------------------------------------------------------------------
// Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_inspect.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_inspect.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_inspect.h"
#include "service_inspectors/http_inspect/http_test_manager.h"
#include "stream/stream.h"

#include "http2_frame.h"
#include "http2_stream.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

#ifdef REG_TEST
static void print_flow_issues(FILE*, Http2Infractions* const, Http2EventGen* const);
#endif

Http2Inspect::Http2Inspect(const Http2ParaList* params_) : params(params_)
{
#ifdef REG_TEST
    if (params->test_input)
    {
        HttpTestManager::activate_test_input(HttpTestManager::IN_HTTP2);
    }
    if (params->test_output)
    {
        HttpTestManager::activate_test_output(HttpTestManager::IN_HTTP2);
    }
#endif
}

bool Http2Inspect::configure(SnortConfig*)
{
    return true;
}

bool Http2Inspect::get_buf(InspectionBuffer::Type /*ibt*/, Packet* /*p*/, InspectionBuffer& /*b*/)
{
    return false;
}

bool Http2Inspect::get_buf(unsigned id, Packet* p, InspectionBuffer& b)
{
    Http2FlowData* const session_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    if (session_data == nullptr)
        return false;

    // Otherwise we can return buffers for raw packets because frame header is available before
    // frame is reassembled.
    if (session_data->stream_in_hi == Http2Enums::NO_STREAM_ID)
        return false;

    if  (id >= HTTP2_BUFFER__MAX)
        return session_data->hi->get_buf(id - HTTP2_BUFFER__MAX + 1, p, b);

    Http2Stream* const stream = session_data->find_processing_stream();
    assert(stream != nullptr);
    const Field& buffer = stream->get_buf(id);
    if (buffer.length() <= 0)
        return false;

    b.data = buffer.start();
    b.len = buffer.length();
    return true;
}

bool Http2Inspect::get_fp_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    // All current HTTP/2 fast pattern buffers are inherited from http_inspect. Just pass the
    // request on.
    Http2FlowData* const session_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->hi == nullptr))
        return false;

    return session_data->hi->get_fp_buf(ibt, p, b);
}

void Http2Inspect::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(Http2Module::get_profile_stats());

    const SourceId source_id = p->is_from_client() ? SRC_CLIENT : SRC_SERVER;

    Http2FlowData* const session_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    if (!session_data)
    {
        assert(false);
        return;
    }

    if (session_data->abort_flow[source_id])
    {
        return;
    }

    session_data->set_processing_stream_id(source_id);
    Http2Stream* const stream = session_data->get_processing_stream(source_id,
        params->concurrent_streams_limit);
    if (!stream)
    {
        delete[] session_data->frame_data[source_id];
        session_data->frame_data[source_id] = nullptr;
        session_data->frame_data_size[source_id] = 0;
        session_data->processing_stream_id = NO_STREAM_ID;
        return;
    }

    assert(session_data->processing_stream_id != NO_STREAM_ID);
    session_data->stream_in_hi = stream->get_stream_id();

    Http2Module::increment_peg_counts(PEG_TOTAL_BYTES, (uint64_t)(FRAME_HEADER_LENGTH) +
        session_data->frame_data_size[source_id]);

    uint8_t* const frame_header_copy = new uint8_t[FRAME_HEADER_LENGTH];
    memcpy(frame_header_copy, session_data->lead_frame_header[source_id], FRAME_HEADER_LENGTH);
    stream->eval_frame(frame_header_copy, FRAME_HEADER_LENGTH,
        session_data->frame_data[source_id], session_data->frame_data_size[source_id], source_id, p);

    if (!stream->get_current_frame()->is_detection_required())
        DetectionEngine::disable_all(p);

    // The current frame now owns these buffers, clear them from the flow data
    session_data->frame_data[source_id] = nullptr;
    session_data->frame_data_size[source_id] = 0;

    session_data->frame_in_detection = true;

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
        stream->print_frame(HttpTestManager::get_output_file());
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
        {
            printf("Finished processing section from test %" PRIi64 "\n",
                HttpTestManager::get_test_number());
        }
        print_flow_issues(HttpTestManager::get_output_file(), session_data->infractions[source_id],
            session_data->events[source_id]);
    }
#endif
}

void Http2Inspect::clear(Packet* p)
{
    Http2FlowData* const session_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    if (session_data == nullptr)
    {
        assert(false);
        return;
    }

    if (!session_data->frame_in_detection)
    {
        assert(session_data->stream_in_hi == NO_STREAM_ID);
        return;
    }

    session_data->frame_in_detection = false;

    Http2Stream* stream = session_data->find_processing_stream();
    assert(stream != nullptr);
    stream->clear_frame(p);
    if (session_data->delete_stream)
        session_data->delete_processing_stream();
    session_data->stream_in_hi = NO_STREAM_ID;
    session_data->processing_stream_id = NO_STREAM_ID;
    session_data->processing_partial_header = false;
    session_data->set_hi_msg_section(nullptr);
}

void Http2Inspect::show(const SnortConfig*) const
{
    assert(params);
    ConfigLogger::log_value("concurrent_streams_limit", params->concurrent_streams_limit);
}

#ifdef REG_TEST
static void print_flow_issues(FILE* output, Http2Infractions* const infractions,
    Http2EventGen* const events)
{
    fprintf(output, "Infractions: %016" PRIx64 ", Events: %016" PRIx64 "\n\n",
        infractions->get_raw(0), events->get_raw(0));
}
#endif

static const uint8_t* get_frame_pdu(Packet* p, uint16_t& length)
{
    auto* const session_data = (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);
    if (!session_data)
        return nullptr;

    auto* stream = session_data->find_processing_stream();
    if (!stream)
        return nullptr;

    auto* frame = stream->get_current_frame();
    if (!frame)
        return nullptr;

    return frame->get_frame_pdu(length);
}

const uint8_t* Http2Inspect::adjust_log_packet(Packet* p, uint16_t& length)
{
    const uint8_t* pdu = get_frame_pdu(p, length);
    if (pdu or !p->has_parent())
        return pdu;

    // for rebuilt packet w/o frame fall back to wire packet
    Packet* wire_packet = DetectionEngine::get_current_wire_packet();
    if (!wire_packet or !wire_packet->data or !wire_packet->dsize)
        return nullptr;

    uint8_t* wire_pdu = new uint8_t[wire_packet->dsize];
    memcpy(wire_pdu, wire_packet->data, wire_packet->dsize);
    length = wire_packet->dsize;

    return wire_pdu;
}
