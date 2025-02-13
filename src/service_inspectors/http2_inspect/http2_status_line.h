//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_status_line.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_STATUS_LINE_H
#define HTTP2_STATUS_LINE_H

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_start_line.h"

class Http2StatusLine : public Http2StartLine
{
public:
    Http2StatusLine(Http2EventGen* const evs, Http2Infractions* const infrs) :
        Http2StartLine(evs, infrs) { }

    void process_pseudo_header(const Field& name, const Field& value) override;
    bool generate_start_line(Field& start_line, bool pseudo_headers_complete) override;

private:
    Field status;

    static const char* STATUS_NAME;
    static const uint32_t STATUS_NAME_LENGTH = 7;
    static const uint32_t RESPONSE_PSEUDO_MIN_INDEX = 8;

};

#endif
