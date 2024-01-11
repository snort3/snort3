//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// http2_utils.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_utils.h"

#include <cassert>

#include "http2_enum.h"

using namespace Http2Enums;

uint32_t get_frame_length(const uint8_t* frame_header_buffer)
{
    return (frame_header_buffer[0] << 16) + (frame_header_buffer[1] << 8) + frame_header_buffer[2];
}

uint8_t get_frame_type(const uint8_t* frame_header_buffer)
{
    const uint8_t frame_type_index = 3;
    if (frame_header_buffer)
        return frame_header_buffer[frame_type_index];
    // If there was no frame header, this must be a piece of a long data frame
    else
        return FT_DATA;
}

uint8_t get_frame_flags(const uint8_t* frame_header_buffer)
{
    const uint8_t frame_flags_index = 4;
    if (frame_header_buffer)
        return frame_header_buffer[frame_flags_index];
    else
        return FLAG_NO_HEADER;
}

uint32_t get_stream_id_from_header(const uint8_t* frame_header_buffer)
{
    const uint8_t stream_id_index = 5;
    assert(frame_header_buffer != nullptr);
    return get_stream_id_from_buffer(frame_header_buffer + stream_id_index);

}

uint32_t get_stream_id_from_buffer(const uint8_t* buffer)
{
    return ((buffer[0] & 0x7f) << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];
}
