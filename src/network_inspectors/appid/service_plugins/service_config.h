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

#include <appid.h>
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

struct ServiceSslConfig
{
    DetectorSSLCertPattern* DetectorSSLCertPatternList;
    DetectorSSLCertPattern* DetectorSSLCnamePatternList;
    SearchTool* ssl_host_matcher;
    SearchTool* ssl_cname_matcher;
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

struct ServiceDnsConfig
{
    DetectorDNSHostPattern* DetectorDNSHostPatternList;
    SearchTool* dns_host_host_matcher;
};

struct ServicePatternData
{
    ServicePatternData* next;
    int position;
    unsigned size;
    RNAServiceElement* svc;
};

struct ServiceConfig
{
    RNAServiceValidationModule* active_service_list; // List of all services (Lua and C)
    RNAServiceElement* tcp_service_list;             // List of all TCP services (Lua and C)
    RNAServiceElement* udp_service_list;             // List of all UDP services (Lua and C)
    RNAServiceElement* udp_reversed_service_list;    // List of all UDP reversed services (Lua and C)

    //list nodes are RNAServiceElement*.
    SF_LIST* tcp_services[RNA_SERVICE_MAX_PORT];
    SF_LIST* udp_services[RNA_SERVICE_MAX_PORT];
    SF_LIST* udp_reversed_services[RNA_SERVICE_MAX_PORT];

    SearchTool* tcp_patterns;
    ServicePatternData* tcp_pattern_data;
    int tcp_pattern_count;
    SearchTool* udp_patterns;
    ServicePatternData* udp_pattern_data;
    int udp_pattern_count;
};

#endif
