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

// service_config.h author Sourcefire Inc.

#ifndef SERVICE_CONFIG_H
#define SERVICE_CONFIG_H

// Service detector configuration

#include <cstdint>

#include "service_api.h"

#define RNA_SERVICE_MAX_PORT 65536

struct RNAServiceElement;
struct RNAServiceValidationModule;
class SearchTool;

struct SSLCertPattern
{
    uint8_t type;
    AppId appId;
    uint8_t* pattern;
    int pattern_size;
};

struct DetectorSSLCertPattern
{
    SSLCertPattern* dpattern;
    DetectorSSLCertPattern* next;
};

// DNS host pattern structure
struct DNSHostPattern
{
    uint8_t type;
    AppId appId;
    uint8_t* pattern;
    int pattern_size;
};

struct DetectorDNSHostPattern
{
    DNSHostPattern* dpattern;
    DetectorDNSHostPattern* next;
};

struct ServicePatternData
{
    ServicePatternData* next;
    int position;
    unsigned size;
    RNAServiceElement* svc;
};

class ServiceConfig
{
public:
    ServiceConfig() {}
    ~ServiceConfig() {}

    // Lists of services (Lua and C)
    RNAServiceValidationModule* active_service_list = nullptr;
    RNAServiceElement* tcp_service_list = nullptr;
    RNAServiceElement* udp_service_list = nullptr;
    RNAServiceElement* udp_reversed_service_list = nullptr;

    //list nodes are RNAServiceElement*.
    SF_LIST* tcp_services[RNA_SERVICE_MAX_PORT] = { nullptr };
    SF_LIST* udp_services[RNA_SERVICE_MAX_PORT] = { nullptr };
    SF_LIST* udp_reversed_services[RNA_SERVICE_MAX_PORT] = { nullptr };

    SearchTool* tcp_patterns = nullptr;
    ServicePatternData* tcp_pattern_data = nullptr;
    int tcp_pattern_count = 0;
    SearchTool* udp_patterns = nullptr;
    ServicePatternData* udp_pattern_data = nullptr;
    int udp_pattern_count = 0;
};

#endif
