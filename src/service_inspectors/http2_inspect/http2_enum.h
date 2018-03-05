//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// http2_enum.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_ENUM_H
#define HTTP2_ENUM_H

#include <cstdint>

namespace Http2Enums
{
static const int MAX_OCTETS = 63780;
static const int DATA_SECTION_SIZE = 16384;
static const int FRAME_HEADER_LENGTH = 9;

// FIXIT-M need to replace with a real number
static const uint32_t HTTP2_GID = 219;

// Message originator--client or server
enum SourceId { SRC__NOT_COMPUTE=-14, SRC_CLIENT=0, SRC_SERVER=1 };

// Frame type codes (fourth octet of frame header)
enum FrameType { FT_DATA=0, FT_HEADERS=1, FT_PRIORITY=2, FT_RST_STREAM=3, FT_SETTINGS=4,
    FT_PUSH_PROMISE=5, FT_PING=6, FT_GOAWAY=7, FT_WINDOW_UPDATE=8, FT_CONTINUATION=9 };

// Message buffers available to clients
// This enum must remain synchronized with Http2Api::classic_buffer_names[]
enum HTTP2_BUFFER { HTTP2_BUFFER_FRAME_HEADER = 1, HTTP2_BUFFER_FRAME_DATA, HTTP2_BUFFER_MAX };

// Peg counts
// This enum must remain synchronized with Http2Module::peg_names[] in http2_tables.cc
enum PEG_COUNT { PEG_CONCURRENT_SESSIONS = 0, PEG_MAX_CONCURRENT_SESSIONS, PEG_FLOW,
    PEG_COUNT_MAX };

enum EventSid
{
    EVENT__NONE = -1,
    EVENT__MAX_VALUE
};

} // end namespace Http2Enums

#endif

