//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// http_events.cc author Steve Chew <stechew@cisco.com>
// Inspection events published by the Http Inspector. Modules can subscribe
// to receive the events.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_events.h"

#include "service_inspectors/http_inspect/http_msg_header.h"
#include "service_inspectors/http_inspect/http_msg_request.h"
#include "service_inspectors/http_inspect/http_uri.h"

using namespace snort;

const uint8_t* HttpEvent::get_header(unsigned id, uint64_t sub_id, int32_t& length)
{
    const Field& field = http_msg_header->get_classic_buffer(id, sub_id, 0);
    if (field.length() > 0)
    {
        length = field.length();
        return field.start();
    }
    else
    {
        length = 0;
        return nullptr;
    }
}

// Returns all HTTP headers plus cookies.
const uint8_t* HttpEvent::get_all_raw_headers(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_RAW_HEADER, 0, length);
}

const uint8_t* HttpEvent::get_content_type(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER,
        HttpEnums::HEAD_CONTENT_TYPE, length);
}

const uint8_t* HttpEvent::get_cookie(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_COOKIE,
        length);
}

const uint8_t* HttpEvent::get_authority(int32_t& length)
{
    // Use authority when available
    HttpMsgRequest* request = http_msg_header->get_request();
    if (request)
    {
        HttpUri* const uri = request->get_http_uri();
        if (uri)
        {
            length = uri->get_authority().length();
            if (length > 0)
                return uri->get_authority().start();
        }
    }
    // Otherwise use host header
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_HOST, length);
}

const uint8_t* HttpEvent::get_uri_host(int32_t &length)
{
    const uint8_t* uri_host = get_header(HttpEnums::HTTP_BUFFER_URI, HttpEnums::UC_HOST, length);
    if (length > 0)
        return uri_host;

    // If there is no authority in the URI parse the host from the Host header
    const Field& host_header = http_msg_header->get_classic_buffer(HttpEnums::HTTP_BUFFER_HEADER,
        HttpEnums::HEAD_HOST, length);
    if (host_header.length() > 0)
    {
        length = HttpUri::find_host_len(host_header);
        return host_header.start();
    }
    else
    {
        length = 0;
        return nullptr;
    }
}

const uint8_t* HttpEvent::get_uri_query(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_URI, HttpEnums::UC_QUERY, length);
}

const uint8_t* HttpEvent::get_location(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_LOCATION,
        length);
}

const uint8_t* HttpEvent::get_referer(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_REFERER,
        length);
}

const uint8_t*  HttpEvent::get_response_phrase(int32_t &length)
{
    return get_header(HttpEnums::HTTP_BUFFER_STAT_MSG, 0, length);
}

int32_t HttpEvent::get_response_code()
{
    return http_msg_header->get_status_code_num();
}

const uint8_t* HttpEvent::get_server(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_SERVER,
        length);
}

const uint8_t* HttpEvent::get_trueip_addr(int32_t& length)
{
    const Field& field = http_msg_header->get_true_ip_addr();
    if (field.length() > 0)
    {
        length = field.length();
        return field.start();
    }
    else
    {
        length = 0;
        return nullptr;
    }
}

const uint8_t* HttpEvent::get_uri(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_URI, 0, length);
}

const uint8_t* HttpEvent::get_user_agent(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_USER_AGENT,
        length);
}

const uint8_t* HttpEvent::get_via(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_VIA,
        length);
}

const uint8_t* HttpEvent::get_x_working_with(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER,
        HttpEnums::HEAD_X_WORKING_WITH, length);
}

const uint8_t* HttpEvent::get_method(int32_t& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_METHOD, 0, length);
}

bool HttpEvent::contains_webdav_method()
{
    HttpEnums::MethodId method = http_msg_header->get_method_id();

    return HttpMsgRequest::is_webdav(method);
}

bool HttpEvent::get_is_httpx() const
{
    return is_httpx;
}

int64_t HttpEvent::get_httpx_stream_id() const
{
    return httpx_stream_id;
}
