//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_body_event.h author Vitalii Tron <vtron@cisco.com>

#ifndef HTTP_BODY_EVENT_H
#define HTTP_BODY_EVENT_H

#include "framework/data_bus.h"

namespace snort
{

// This event is published each time new request or response body data is received by http_inspect for HTTP traffic.
// The body may be published in several pieces, concluded by the publication with last_piece == true.
class SO_PUBLIC HttpBodyEvent : public snort::DataEvent
{
public:
    HttpBodyEvent(const uint8_t* http_body_ptr, const int32_t http_body_length,
        const bool is_data_originates_from_client, const bool last_piece)
        : http_body_ptr(http_body_ptr), http_body_length(http_body_length),
        is_data_originates_from_client(is_data_originates_from_client), last_piece(last_piece) { }
    const uint8_t* get_body(int32_t& length) const;
    bool is_data_from_client() const { return is_data_originates_from_client; }
    bool is_last_piece() const { return last_piece; }

private:
    const uint8_t* http_body_ptr;
    const int32_t http_body_length;
    const bool is_data_originates_from_client;
    const bool last_piece;
};

} // namespace snort
#endif
