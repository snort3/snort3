//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_test_manager.h"
#include "stream/stream.h"

using namespace snort;
using namespace Http2Enums;

Http2Inspect::Http2Inspect(const Http2ParaList* params_) : params(params_)
{
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

    const SourceId source_id = p->is_from_client() ? SRC_CLIENT : SRC_SERVER;

    return implement_get_buf(id, session_data, source_id, b);
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

    set_file_data(session_data->frame_data[source_id], session_data->frame_data_size[source_id]);
    session_data->frame_in_detection = true;

#ifdef REG_TEST
    if (HttpTestManager::use_test_output())
    {
        Field((session_data->frame_header[source_id] != nullptr) ? FRAME_HEADER_LENGTH :
            HttpEnums::STAT_NOT_PRESENT,
            session_data->frame_header[source_id]).print(stdout, "frame header");
        Field((session_data->frame_data[source_id] != nullptr) ?
            (int) session_data->frame_data_size[source_id] : HttpEnums::STAT_NOT_PRESENT,
            session_data->frame_data[source_id]).print(stdout, "frame data");
    }
#endif
}

void Http2Inspect::clear(Packet* p)
{
    Http2FlowData* const session_data =
        (Http2FlowData*)p->flow->get_flow_data(Http2FlowData::inspector_id);

    if (session_data == nullptr)
        return;

    const SourceId source_id = (p->is_from_client()) ? SRC_CLIENT : SRC_SERVER;

    delete[] session_data->frame_header[source_id];
    session_data->frame_header[source_id] = nullptr;
    delete[] session_data->frame[source_id];
    session_data->frame[source_id] = nullptr;
    session_data->frame_in_detection = false;
}

