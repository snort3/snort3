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
// http2_inspect_impl.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_inspect.h"
#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_frame.h"
#include "service_inspectors/http_inspect/http_common.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

bool implement_get_buf(unsigned id, Http2FlowData* session_data, SourceId source_id,
    InspectionBuffer& b)
{
    const Field& buffer = session_data->current_frame[source_id]->get_buf(id);
    if (buffer.length() <= 0)
        return false;
    b.data = buffer.start();
    b.len = buffer.length();
    return true;
}

void implement_eval(Http2FlowData* session_data, SourceId source_id)
{
    // Construct the appropriate frame class
    session_data->current_frame[source_id] = Http2Frame::new_frame(
        session_data->frame_header[source_id], session_data->frame_header_size[source_id],
        session_data->frame_data[source_id], session_data->frame_data_size[source_id],
        session_data, source_id);
    // The current frame now owns these buffers, clear them from the flow data
    session_data->frame_header[source_id] = nullptr;
    session_data->frame_data[source_id] = nullptr;
}
