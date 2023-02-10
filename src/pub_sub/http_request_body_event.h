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
// http_request_body_event.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP_REQUEST_BODY_EVENT_H
#define HTTP_REQUEST_BODY_EVENT_H

#include "framework/data_bus.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_msg_body.h"

#include "http_event_ids.h"

class HttpFlowData;

namespace snort
{
// This event is published each time new request body data is received by http_inspect for HTTP/2
// traffic, up to the publish depth. The full request body may be sent in several pieces
class SO_PUBLIC HttpRequestBodyEvent : public snort::DataEvent
{
public:
    HttpRequestBodyEvent(HttpMsgBody* msg_body, int32_t offset, bool last, HttpFlowData* flow_data)
        : http_msg_body(msg_body), msg_offset(offset), last_piece(last), http_flow_data(flow_data)
        { }

    const uint8_t* get_request_body_data(int32_t& length, int32_t& offset);
    bool is_last_request_body_piece();
    int64_t get_httpx_stream_id() const;

private:
    const HttpMsgBody* const http_msg_body;
    const int32_t msg_offset;
    const bool last_piece;
    HttpFlowData* const http_flow_data;
};
}
#endif

