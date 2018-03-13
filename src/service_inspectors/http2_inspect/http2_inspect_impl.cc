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
// http2_inspect_impl.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_inspect.h"
#include "http2_flow_data.h"

using namespace snort;
using namespace Http2Enums;

bool implement_get_buf(unsigned id, Http2FlowData* session_data, SourceId source_id,
    InspectionBuffer& b)
{
    switch (id)
    {
    case HTTP2_BUFFER_FRAME_HEADER:
        if (session_data->frame_header[source_id] == nullptr)
            return false;
        b.data = session_data->frame_header[source_id];
        b.len = FRAME_HEADER_LENGTH;
        break;
    case HTTP2_BUFFER_FRAME_DATA:
        if (session_data->frame_data[source_id] == nullptr)
            return false;
        b.data = session_data->frame_data[source_id];
        b.len = session_data->frame_data_size[source_id];
        break;
    default:
        return false;
    }
    return true;
}

