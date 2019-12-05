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
    { EVENT_INT_DECODE_FAILURE, "error in HPACK integer value" },
    { EVENT_INT_LEADING_ZEROS, "HPACK integer value has leading zeros" },
    { EVENT_STRING_DECODE_FAILURE, "error in HPACK string value" },
    { EVENT_MISSING_CONTINUATION, "missing HTTP/2 continuation frame" },
    { EVENT_UNEXPECTED_CONTINUATION, "unexpected HTTP/2 continuation frame" },
    { EVENT_MISFORMATTED_HTTP2, "misformatted HTTP/2 traffic" },
    { EVENT_PREFACE_MATCH_FAILURE, "HTTP/2 connection preface does not match" },
    { EVENT_REQUEST_WITHOUT_REQUIRED_FIELD, "HTTP/2 request missing required header field" },
    { EVENT_RESPONSE_WITHOUT_STATUS, "HTTP/2 response has no status code" },
    { EVENT_INVALID_HEADER, "invalid HTTP/2 header field" },
    { EVENT_SETTINGS_FRAME_ERROR, "error in HTTP/2 settings frame" },
    { EVENT_SETTINGS_FRAME_UNKN_PARAM, "unknown parameter in HTTP/2 settings frame" },
    { 0, nullptr }
};

const PegInfo Http2Module::peg_names[PEG_COUNT_MAX+1] =
{
    { CountType::SUM, "flows", "HTTP connections inspected" },
    { CountType::NOW, "concurrent_sessions", "total concurrent HTTP/2 sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent HTTP/2 sessions" },
    { CountType::END, nullptr, nullptr }
};

