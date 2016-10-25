//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "http_events.h"
#include "service_inspectors/http_inspect/http_msg_header.h"

const uint8_t* HttpEvent::get_header(unsigned id, uint64_t sub_id, unsigned& length)
{
    Field field;
    field = http_msg_header->get_classic_buffer(id, sub_id, 0);
    if(field.length > 0)
    {
        length = field.length;
        return field.start;
    }
    else
    {
        length = 0;
        return nullptr;
    }
}

const uint8_t* HttpEvent::get_content_type(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, 
        HttpEnums::HEAD_CONTENT_TYPE, length);
}

const uint8_t* HttpEvent::get_host(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_HOST,
        length);
}

const uint8_t* HttpEvent::get_referer(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_REFERER,
        length);
}

int32_t HttpEvent::get_response_code()
{
    return http_msg_header->get_status_code();
}

const uint8_t* HttpEvent::get_server(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_SERVER,
        length);
}

const uint8_t* HttpEvent::get_uri(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_URI, 0, length);
}

const uint8_t* HttpEvent::get_user_agent(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_USER_AGENT,
        length);
}

const uint8_t* HttpEvent::get_via(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, HttpEnums::HEAD_VIA, 
        length);
}

const uint8_t* HttpEvent::get_x_working_with(unsigned& length)
{
    return get_header(HttpEnums::HTTP_BUFFER_HEADER, 
        HttpEnums::HEAD_X_WORKING_WITH, length);
}

