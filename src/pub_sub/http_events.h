//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// These are common values between the HTTP inspector and the subscribers.
#define HTTP_REQUEST_HEADER_EVENT_KEY "http_request_header_event"
#define HTTP_RESPONSE_HEADER_EVENT_KEY "http_response_header_event"

class HttpMsgHeader;

namespace snort
{
class SO_PUBLIC HttpEvent : public snort::DataEvent
{
public:
    HttpEvent(HttpMsgHeader* http_msg_header_) :
        http_msg_header(http_msg_header_)
    {
    }


    const uint8_t* get_content_type(int32_t &length);
    const uint8_t* get_cookie(int32_t &length);
    const uint8_t* get_host(int32_t &length);
    const uint8_t* get_location(int32_t &length);
    const uint8_t* get_referer(int32_t &length);
    const uint8_t* get_server(int32_t &length);
    const uint8_t* get_uri(int32_t &length);
    const uint8_t* get_user_agent(int32_t &length);
    const uint8_t* get_via(int32_t &length);
    const uint8_t* get_x_working_with(int32_t &length);
    int32_t get_response_code();
    bool contains_webdav_method();

private:
    HttpMsgHeader* const http_msg_header;

    const uint8_t* get_header(unsigned, uint64_t, int32_t&);

};
}
#endif

