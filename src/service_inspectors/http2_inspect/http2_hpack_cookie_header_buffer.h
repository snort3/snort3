//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_hpack_cookie_header_buffer.h author Jaime Andres Castillo Leon <jaimeaca@cisco.com>

#ifndef HTTP2_HPACK_COOKIE_HEADER_BUFFER_H
#define HTTP2_HPACK_COOKIE_HEADER_BUFFER_H

#include <cstdint>
#include <string>

#include "helpers/infractions.h"
#include "http2_enum.h"

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;

class Http2CookieHeaderBuffer final
{
    using u8string = std::basic_string<uint8_t>;
public:
    void append_value(const uint8_t* start, int32_t length);
    bool append_header_in_decoded_headers(uint8_t* decoded_header_buffer,
        const uint32_t decoded_header_length, const uint32_t decoded_header_capacity,
        uint32_t& bytes_written, Http2Infractions* const infractions);
    bool has_headers() const;

    static bool is_cookie(const uint8_t* start, int32_t length)
    {
        return length > 0  && (uint32_t)length == cookie_key_size &&
            std::equal(start, start + length, cookie_key);
    }

private:
    u8string buffer = (const uint8_t*)"";

    static const uint32_t initial_buffer_size = 1024;
    static const uint8_t* cookie_key;
    static const uint32_t cookie_key_size = 6;
};

#endif // HTTP2_HPACK_COOKIE_HEADER_BUFFER_H
