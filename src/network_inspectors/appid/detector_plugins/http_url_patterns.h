//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// http_url_patterns.h author Sourcefire Inc.

#ifndef HTTP_URL_PATTERNS_H
#define HTTP_URL_PATTERNS_H

// List of URL pattern match functions

#include "http_common.h"

struct tMlmpPattern;

int addMlmpPattern(void* mlpMatcher, HosUrlPatternsList** hosUrlPatternsList, const
    uint8_t* host_pattern, int host_pattern_size,
    const uint8_t* path_pattern, int path_pattern_size, const uint8_t* query_pattern, int
    query_pattern_size,
    AppId appId, uint32_t payload_id, uint32_t service_id, uint32_t client_id, DHPSequence seq);
void destroyHosUrlMatcher(tMlmpTree** mlpMatcher);
int matchQueryElements(tMlpPattern* packetData,
    tMlpPattern* userPattern,
    char* appVersion,
    size_t appVersionSize);

uint32_t parseMultipleHTTPPatterns(const char* pattern, tMlmpPattern* parts, u_int32_t
    numPartLimit, int level);
void destroyHosUrlPatternList(HosUrlPatternsList** pHosUrlPatternsList);

#endif

