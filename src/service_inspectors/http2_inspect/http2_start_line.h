//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_start_line.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_START_LINE_H
#define HTTP2_START_LINE_H

#include "helpers/event_gen.h"
#include "helpers/infractions.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;
using Http2EventGen = EventGen<Http2Enums::EVENT__MAX_VALUE, Http2Enums::EVENT__NONE,
    Http2Enums::HTTP2_GID>;

class Http2FlowData;

class Http2StartLine
{
public:
    virtual ~Http2StartLine();

    friend class Http2Hpack;

    virtual bool generate_start_line(Field& start_line, bool pseudo_headers_complete) = 0;
    virtual void process_pseudo_header(const Field& name, const Field& value) = 0;

protected:
    Http2StartLine(Http2EventGen* const events, Http2Infractions* const infractions) :
        events(events), infractions(infractions) { }

    Http2EventGen* const events;
    Http2Infractions* const infractions;
    uint32_t start_line_length = 0;
    uint8_t *start_line_buffer = nullptr;

    // Version string is HTTP/1.1
    static const char* http_version_string;
    static const uint8_t http_version_length = 8;
};

#endif
