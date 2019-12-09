//--------------------------------------------------------------------------
// Copyright (C) 2018-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "service_inspectors/http_inspect/http_test_manager.h"
#include "stream/stream.h"

#include "http2_frame.h"
#include "http2_stream.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

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
    if ((params->test_input) || (params->test_output))
    {
        HttpTestManager::set_print_amount(params->print_amount);
        HttpTestManager::set_print_hex(params->print_hex);
        HttpTestManager::set_show_pegs(params->show_pegs);
        HttpTestManager::set_show_scan(params->show_scan);
    }
#endif
}

bool Http2Inspect::configure(SnortConfig* )
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
    if (!session_data->frame_in_detection)
        return false;

    const Field& buffer = session_data->stream->get_buf(id);
    if (buffer.length() <= 0)
        return false;

    b.data = buffer.start();
    b.len = buffer.length();
    return true;
}

bool Http2Inspect::get_fp_buf(InspectionBuffer::Type /*ibt*/, Packet* /*p*/,
    InspectionBuffer& /*b*/)
{
    // No fast pattern buffers have been defined for HTTP/2
    return false;
}

void Http2Inspect::eval(Packet* p)
{
    Profile profile(Http2Module::get_profile_stats());

    const SourceId source_id = p->is_from_client() ? SRC_CLIENT : SRC_SERVER;

    Http2FlowData* const session_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    // FIXIT-H Workaround for unexpected eval() calls
    // Avoid eval if scan/reassemble aborts
    if (session_data->frame_type[source_id] == FT__NONE)
        return;

    session_data->stream->eval_frame(session_data->frame_header[source_id],
        session_data->frame_header_size[source_id], session_data->frame_data[source_id],
        session_data->frame_data_size[source_id], source_id);

    // The current frame now owns these buffers, clear them from the flow data
    session_data->frame_header[source_id] = nullptr;
    session_data->frame_data[source_id] = nullptr;

    session_data->frame_in_detection = true;

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
        session_data->stream->print_frame(HttpTestManager::get_output_file());
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP2))
        {
            printf("Finished processing section from test %" PRIi64 "\n",
                HttpTestManager::get_test_number());
        }
    }
#endif
}

void Http2Inspect::clear(Packet* p)
{
    Http2FlowData* const session_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    if (session_data == nullptr)
        return;

    session_data->frame_in_detection = false;
    session_data->stream->clear_frame();
}

