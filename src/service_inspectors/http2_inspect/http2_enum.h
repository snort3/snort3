//--------------------------------------------------------------------------
// Copyright (C) 2018-2019 Cisco and/or its affiliates. All rights reserved.
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

static const uint32_t HTTP2_GID = 121;

// Frame type codes (fourth octet of frame header)
enum FrameType : uint8_t { FT_DATA=0, FT_HEADERS=1, FT_PRIORITY=2, FT_RST_STREAM=3, FT_SETTINGS=4,
    FT_PUSH_PROMISE=5, FT_PING=6, FT_GOAWAY=7, FT_WINDOW_UPDATE=8, FT_CONTINUATION=9, FT__ABORT=254,
    FT__NONE=255 };

// Message buffers available to clients
// This enum must remain synchronized with Http2Api::classic_buffer_names[]
enum HTTP2_BUFFER { HTTP2_BUFFER_FRAME_HEADER = 1, HTTP2_BUFFER_FRAME_DATA, HTTP2_BUFFER_DECODED_HEADER, 
    HTTP2_BUFFER_MAX };

// Peg counts
// This enum must remain synchronized with Http2Module::peg_names[] in http2_tables.cc
enum PEG_COUNT { PEG_CONCURRENT_SESSIONS = 0, PEG_MAX_CONCURRENT_SESSIONS, PEG_FLOW,
    PEG_COUNT_MAX };

enum EventSid
{
    EVENT__NONE = -1,
    EVENT_INT_DECODE_FAILURE = 1,
    EVENT_INT_LEADING_ZEROS = 2,
    EVENT_STRING_DECODE_FAILURE = 3,
    EVENT_MISSING_CONTINUATION = 4,
    EVENT_UNEXPECTED_CONTINUATION = 5,
    EVENT_MISFORMATTED_HTTP2 = 6,
    EVENT_PREFACE_MATCH_FAILURE = 7,
    EVENT_REQUEST_WITHOUT_REQUIRED_FIELD = 8,
    EVENT_RESPONSE_WITHOUT_STATUS = 9,
    EVENT_INVALID_HEADER = 10,
    EVENT_SETTINGS_FRAME_ERROR = 11,
    EVENT_SETTINGS_FRAME_UNKN_PARAM = 12,
    EVENT__MAX_VALUE
};

// All the infractions we might find while parsing and analyzing a message
enum Infraction
{
    INF__NONE = -1,
    INF_INT_EMPTY_BUFF = 0,
    INF_INT_MISSING_BYTES = 1,
    INF_INT_OVERFLOW = 2,
    INF_INT_LEADING_ZEROS = 3,
    INF_STRING_EMPTY_BUFF = 4,
    INF_STRING_MISSING_BYTES = 5,
    INF_DECODED_HEADER_BUFF_OUT_OF_SPACE = 6,
    INF_HUFFMAN_BAD_PADDING = 7,
    INF_HUFFMAN_DECODED_EOS = 8,
    INF_HUFFMAN_INCOMPLETE_CODE_PADDING = 9,
    INF_MISSING_CONTINUATION = 10,
    INF_UNEXPECTED_CONTINUATION = 11,
    INF_LOOKUP_EMPTY_VALUE = 12,
    INF_INVALID_PSEUDO_HEADER = 13,
    INF_PSEUDO_HEADER_AFTER_REGULAR_HEADER = 14,
    INF_PSEUDO_HEADER_URI_FORM_MISMATCH = 15,
    INF_RESPONSE_WITHOUT_STATUS = 16,
    INF_HPACK_INDEX_OUT_OF_BOUNDS = 17,
    INF_INVALID_SETTINGS_FRAME = 18,
    INF_SETTINGS_FRAME_UNKN_PARAM = 19,
    INF__MAX_VALUE
};

enum HeaderFrameFlags 
{
    END_STREAM = 0x1,
    END_HEADERS = 0x4,
    PADDED = 0x8,
    PRIORITY = 0x20,
    NO_HEADER = 0x80, //No valid flags use this bit
};

enum PseudoHeaders
{
    HEADER__INVALID = -1,
    HEADER__NONE = 0,
    AUTHORITY = 1,
    METHOD = 3,
    PATH = 5,
    SCHEME = 7,
    STATUS = 14,
};

enum SettingsFrameIds
{
    HEADER_TABLE_SIZE = 1,
    ENABLE_PUSH, 
    MAX_CONCURRENT_STREAMS,
    INITIAL_WINDOW_SIZE,
    MAX_FRAME_SIZE,
    MAX_HEADER_LIST_SIZE,
};

} // end namespace Http2Enums

#endif

