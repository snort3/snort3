//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// http2_start_line.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_start_line.h"

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"
#include "http2_flow_data.h"

using namespace HttpCommon;
using namespace Http2Enums;

const char* Http2StartLine::http_version_string = "HTTP/1.1";

Http2StartLine::Http2StartLine(Http2FlowData* _session_data, HttpCommon::SourceId _source_id) :
   session_data(_session_data), source_id(_source_id)
{ }

bool Http2StartLine::process_pseudo_header_precheck()
{
    if (finalized)
    {
        *session_data->infractions[source_id] += INF_PSEUDO_HEADER_AFTER_REGULAR_HEADER;
        session_data->events[source_id]->create_event(EVENT_MISFORMATTED_HTTP2);
        return false;
    }
    return true;
}

bool Http2StartLine::finalize()
{
    finalized = true;

    // Save the current position in the raw decoded buffer so we can set the pointer to the start
    // of the regular headers
    session_data->pseudo_header_fragment_size[source_id] =
        session_data->raw_decoded_header_size[source_id];

    return generate_start_line();
}
