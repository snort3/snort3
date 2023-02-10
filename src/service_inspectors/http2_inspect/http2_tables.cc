//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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
// http2_tables.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/counts.h"

#include "http2_enum.h"
#include "http2_module.h"

using namespace Http2Enums;
using namespace snort;

const RuleMap Http2Module::http2_events[] =
{
    { EVENT_INVALID_FLAG, "invalid flag set on HTTP/2 frame" },
    { EVENT_INT_LEADING_ZEROS, "HPACK integer value has leading zeros" },
    { EVENT_INVALID_STREAM_ID, "HTTP/2 stream initiated with invalid stream id" },
    { EVENT_MISSING_CONTINUATION, "missing HTTP/2 continuation frame" },
    { EVENT_UNEXPECTED_CONTINUATION, "unexpected HTTP/2 continuation frame" },
    { EVENT_MISFORMATTED_HTTP2, "HTTP/2 headers HPACK decoding error" },
    { EVENT_PREFACE_MATCH_FAILURE, "HTTP/2 connection preface does not match" },
    { EVENT_REQUEST_WITHOUT_REQUIRED_FIELD, "HTTP/2 request missing required header field" },
    { EVENT_RESPONSE_WITHOUT_STATUS, "HTTP/2 response has no status code" },
    { EVENT_CONNECT_WITH_SCHEME_OR_PATH, "HTTP/2 CONNECT request with scheme or path" },
    { EVENT_SETTINGS_FRAME_ERROR, "error in HTTP/2 settings frame" },
    { EVENT_SETTINGS_FRAME_UNKN_PARAM, "unknown parameter in HTTP/2 settings frame" },
    { EVENT_FRAME_SEQUENCE, "invalid HTTP/2 frame sequence" },
    { EVENT_DYNAMIC_TABLE_OVERFLOW, "HTTP/2 dynamic table has more than 512 entries" },
    { EVENT_INVALID_PROMISED_STREAM, "HTTP/2 push promise frame with promised stream ID already in use" },
    { EVENT_PADDING_LEN, "HTTP/2 padding length is bigger than frame data size" },
    { EVENT_PSEUDO_HEADER_AFTER_REGULAR_HEADER, "HTTP/2 pseudo-header after regular header" },
    { EVENT_PSEUDO_HEADER_IN_TRAILERS, "HTTP/2 pseudo-header in trailers" },
    { EVENT_INVALID_PSEUDO_HEADER, "invalid HTTP/2 pseudo-header" },
    { EVENT_TRAILERS_NOT_END, "HTTP/2 trailers without END_STREAM bit" },
    { EVENT_PUSH_WHEN_PROHIBITED, "HTTP/2 push promise frame sent when prohibited by receiver" },
    { EVENT_PADDING_ON_EMPTY_FRAME, "padding flag set on HTTP/2 frame with zero length" },
    { EVENT_C2S_PUSH, "HTTP/2 push promise frame in client-to-server direction" },
    { EVENT_INVALID_PUSH_FRAME, "invalid HTTP/2 push promise frame" },
    { EVENT_BAD_PUSH_SEQUENCE, "HTTP/2 push promise frame sent at invalid time" },
    { EVENT_BAD_SETTINGS_VALUE, "invalid parameter value sent in HTTP/2 settings frame" },
    { EVENT_TOO_MANY_STREAMS, "excessive concurrent HTTP/2 streams" },
    { EVENT_INVALID_RST_STREAM_FRAME, "invalid HTTP/2 rst stream frame" },
    { EVENT_BAD_RST_STREAM_SEQUENCE, "HTTP/2 rst stream frame sent at invalid time" },
    { EVENT_HEADER_UPPERCASE, "uppercase HTTP/2 header field name" },
    { EVENT_INVALID_WINDOW_UPDATE_FRAME, "invalid HTTP/2 window update frame" },
    { EVENT_WINDOW_UPDATE_FRAME_ZERO_INCREMENT, "HTTP/2 window update frame with zero increment" },
    { EVENT_REQUEST_WITHOUT_METHOD, "HTTP/2 request without a method" },
    { EVENT_TABLE_SIZE_UPDATE_NOT_AT_HEADER_START, 
        "HTTP/2 HPACK table size update not at the start of a header block" },
    { EVENT_MORE_THAN_2_TABLE_SIZE_UPDATES, 
        "More than two HTTP/2 HPACK table size updates in a single header block" },
    { EVENT_HPACK_TABLE_SIZE_UPDATE_EXCEEDS_MAX,
        "HTTP/2 HPACK table size update exceeds max value set by decoder in SETTINGS frame" },
    { EVENT_UNEXPECTED_DATA_FRAME, "Nonempty HTTP/2 Data frame where message body not expected" },
    { EVENT_NON_DATA_FRAME_TOO_LONG, "HTTP/2 non-Data frame longer than 63780 bytes" },
    { EVENT_LOSS_OF_SYNC,  "not HTTP/2 traffic or unrecoverable HTTP/2 protocol error" },
    { EVENT_INVALID_PRIORITY_FRAME, "invalid HTTP/2 PRIORITY frame" },
    { EVENT_INVALID_GOAWAY_FRAME, "invalid HTTP/2 GOAWAY frame" },
    { 0, nullptr }
};

const PegInfo Http2Module::peg_names[PEG_COUNT__MAX+1] =
{
    { CountType::SUM, "flows", "HTTP/2 connections inspected" },
    { CountType::NOW, "concurrent_sessions", "total concurrent HTTP/2 sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent HTTP/2 sessions" },
    { CountType::MAX, "max_table_entries", "maximum entries in an HTTP/2 dynamic table" },
    { CountType::MAX, "max_concurrent_files", "maximum concurrent file transfers per HTTP/2 connection" },
    { CountType::SUM, "total_bytes", "total HTTP/2 data bytes inspected" },
    { CountType::MAX, "max_concurrent_streams", "maximum concurrent streams per HTTP/2 connection" },
    { CountType::SUM, "flows_over_stream_limit", "HTTP/2 flows exceeding 100 concurrent streams" },
    { CountType::END, nullptr, nullptr }
};

