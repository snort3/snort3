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
#include "http2_request_line.h"
#include "http2_status_line.h"

using namespace HttpCommon;
using namespace Http2Enums;

const char* Http2StartLine::http_version_string = "HTTP/1.1";

Http2StartLine::~Http2StartLine()
{
    delete[] start_line_buffer;
}

Http2StartLine* Http2StartLine::new_start_line_generator(SourceId source_id,
        Http2EventGen* events, Http2Infractions* infractions)
{
    if (source_id == SRC_CLIENT)
        return new Http2RequestLine(events, infractions);
    else
        return new Http2StatusLine(events, infractions);
}

void Http2StartLine::process_pseudo_header_precheck()
{
    if (finalized)
    {
        infractions += INF_PSEUDO_HEADER_AFTER_REGULAR_HEADER;
        events->create_event(EVENT_INVALID_HEADER);
    }
}

bool Http2StartLine::finalize()
{
    finalized = true;
    return generate_start_line();
}

const Field* Http2StartLine::get_start_line()
{
    return new Field(start_line_length, start_line_buffer, false);
}
