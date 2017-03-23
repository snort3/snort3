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

// client_app_config.h author Sourcefire Inc.

#ifndef APPID_DISCOVERY_H
#define APPID_DISCOVERY_H

#include <string>
#include <map>

#include "protocols/protocol_ids.h"
#include "search_engines/search_tool.h"
#include "flow/flow.h"

class HttpPatternMatchers;
class AppIdSession;
class AppIdDetector;
class ServiceDetector;
struct ServiceDetectorPort;
struct Packet;

struct AppIdPatternMatchNode
{
    AppIdPatternMatchNode* next = nullptr;
    int pattern_start_pos = 0;
    unsigned size = 0;
    AppIdDetector* service = nullptr;
};

struct ServiceMatch
{
    struct ServiceMatch* next;
    unsigned count;
    unsigned size;
    ServiceDetector* service = nullptr;
};

typedef std::map<std::string, AppIdDetector*> AppIdDetectors;
typedef AppIdDetectors::iterator AppIdDetectorsIterator;

class AppIdDiscovery
{
public:
    AppIdDiscovery();
    virtual ~AppIdDiscovery();
    static void initialize_plugins();
    static void finalize_plugins();
    static void release_plugins();

    virtual void initialize() = 0;
    virtual void register_detector(std::string, AppIdDetector*,  IpProtocol);
    virtual void add_pattern_data(AppIdDetector*, SearchTool*, int position,
        const uint8_t* const pattern, unsigned size, unsigned nocase, int* count);
    virtual void register_tcp_pattern(AppIdDetector*, const uint8_t* const pattern, unsigned size,
        int position, unsigned nocase);
    virtual void register_udp_pattern(AppIdDetector*, const uint8_t* const pattern, unsigned size,
        int position, unsigned nocase);
    virtual int add_service_port(AppIdDetector*, const ServiceDetectorPort&);

    static void do_application_discovery(Packet* p);

    AppIdDetectors tcp_detectors;
    AppIdDetectors udp_detectors;
    SearchTool* tcp_patterns = nullptr;
    int tcp_pattern_count = 0;
    SearchTool* udp_patterns = nullptr;
    int udp_pattern_count = 0;
    AppIdPatternMatchNode* pattern_data_list = nullptr;
    HttpPatternMatchers* http_matchers;
};
#endif

