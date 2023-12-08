//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// http_events.h author Steve Chew <stechew@cisco.com>
// Inspection events published by the Http Inspector. Modules can subscribe
// to receive the events.

#ifndef HTTP_EVENTS_H
#define HTTP_EVENTS_H

#include "framework/data_bus.h"
#include "pub_sub/http_event_ids.h"

class HttpMsgHeader;

namespace snort
{

class SO_PUBLIC HttpEvent : public snort::DataEvent
{
public:
    HttpEvent(HttpMsgHeader* http_msg_header_, bool httpx, int64_t stream_id) :
        http_msg_header(http_msg_header_), is_httpx(httpx), httpx_stream_id(stream_id) { }

    const uint8_t* get_content_type(int32_t &length);
    const uint8_t* get_cookie(int32_t &length);
    const uint8_t* get_authority(int32_t &length);
    const uint8_t* get_uri_host(int32_t &length);
    const uint8_t* get_uri_query(int32_t &length);
    const uint8_t* get_location(int32_t &length);
    const uint8_t* get_referer(int32_t &length);
    const uint8_t* get_server(int32_t &length);
    const uint8_t* get_trueip_addr(int32_t& length);
    const uint8_t* get_uri(int32_t &length);
    const uint8_t* get_user_agent(int32_t &length);
    const uint8_t* get_via(int32_t &length);
    const uint8_t* get_x_working_with(int32_t &length);
    int32_t get_response_code();
    bool contains_webdav_method();
    bool get_is_httpx() const;
    int64_t get_httpx_stream_id() const;

private:
    HttpMsgHeader* const http_msg_header;
    bool is_httpx = false;
    int64_t httpx_stream_id = -1;

    const uint8_t* get_header(unsigned, uint64_t, int32_t&);

};
}
#endif
