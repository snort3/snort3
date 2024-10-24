//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_hpack_cookie_header_buffer.cc author Jaime Andres Castillo Leon <jaimeaca@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_hpack_cookie_header_buffer.h"

const uint8_t* Http2CookieHeaderBuffer::cookie_key = (const uint8_t*)"cookie";

void Http2CookieHeaderBuffer::append_value(const uint8_t* start, int32_t length)
{
    // (RFC 7230) section 3.2.6 describes the syntax for the value of a header in general, including
    // quoting (RFC 6265) for specifics to cookies.
    if ( !buffer.empty() )
    {
        buffer += (const uint8_t*)"; ";
    }
    else
    {
        // let's initialize the buffer to reduce dynamic allocation for std::basic_string<uint8_t>;
        buffer.reserve(Http2CookieHeaderBuffer::initial_buffer_size);
        buffer = (const uint8_t*)"cookie: ";
    }
    buffer.append(start, length);
}

bool Http2CookieHeaderBuffer::append_header_in_decoded_headers(uint8_t* decoded_header_buffer,
    const uint32_t decoded_header_length, const uint32_t decoded_header_capacity,
    uint32_t& bytes_written, Http2Infractions* const infractions)
{
    if ( !buffer.empty() )
    {
        buffer += (const uint8_t*)"\r\n";
    }
    const u8string& in = buffer;
    const uint32_t in_length = in.length();

    bytes_written = 0;

    const uint32_t new_decoded_header_length = decoded_header_length + in_length;
    if (new_decoded_header_length > decoded_header_capacity)
    {
        *infractions += Http2Enums::Infraction::INF_DECODED_HEADER_BUFF_OUT_OF_SPACE;
        return false;
    }
    else
    {
        std::copy(in.begin(), in.end(), decoded_header_buffer + decoded_header_length);
        bytes_written = in_length;
    }
    return true;
}

bool Http2CookieHeaderBuffer::has_headers() const
{
    return !buffer.empty();
}
