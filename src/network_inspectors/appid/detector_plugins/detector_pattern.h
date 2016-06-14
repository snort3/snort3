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

// detector_pattern.h author Sourcefire Inc.

#ifndef DETECTOR_PATTERN_H
#define DETECTOR_PATTERN_H

#include "appid_api.h"
#include "detector_api.h"

extern RNAServiceValidationModule pattern_service_mod;

struct PortPatternNode
{
    AppId appId;
    IpProtocol protocol;
    unsigned short port;
    unsigned char* pattern;
    unsigned length;
    int32_t offset;
    char* detectorName;
    PortPatternNode* next;
};

struct PatternService;
struct Pattern
{
    Pattern* next;
    unsigned length;
    int offset;
    uint8_t* data;
    PatternService* ps;
};

struct PortNode // FIXIT this name changed from "Port" which is already in use by Snort++
{
    PortNode* next;
    uint16_t port;
};

/**list for pattern services. Each pattern service is unique for a given uuid. */
struct PatternService
{
    PatternService* next;
    AppId id;
    Pattern* pattern;
    PortNode* port;
    IpProtocol proto;
    unsigned count;
    unsigned longest;
};

class SearchTool;
struct ServicePortPattern
{
    PortPatternNode* luaInjectedPatterns;
    PatternService* servicePortPattern;
    SearchTool* tcp_patterns;
    SearchTool* udp_patterns;
    SearchTool* tcpPortPatternTree[65536];
    SearchTool* udpPortPatternTree[65536];
};

struct ClientPortPattern
{
    PortPatternNode* luaInjectedPatterns;
    PatternService* servicePortPattern;
    SearchTool* tcp_patterns;
    SearchTool* udp_patterns;
};

#endif

