//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// http_request_body_event.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_request_body_event.h"

#include "service_inspectors/http_inspect/http_flow_data.h"

using namespace snort;

const uint8_t* HttpRequestBodyEvent::get_request_body_data(int32_t& length, int32_t& offset)
{
    offset = msg_offset;

    if (http_msg_body)
    {
        const Field& body = http_msg_body->get_msg_text_new();
        length = http_msg_body->get_publish_length();
        if (length > 0)
        {
            assert(body.length() >= length);
            return body.start();
        }
    }

    length = 0;
    return nullptr;
}

bool HttpRequestBodyEvent::is_last_request_body_piece()
{
    return last_piece;
}

int64_t HttpRequestBodyEvent::get_httpx_stream_id() const
{
    return http_flow_data->get_hx_stream_id();
}
