//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "client_plugins/client_detector.h"
#include "service_plugins/service_detector.h"

namespace snort
{
class SearchTool;
}

class AppIdInspector;

struct PortPatternNode
{
    AppId appId;
    IpProtocol protocol;
    unsigned short port;
    unsigned char* pattern;
    unsigned length;
    int32_t offset;
    char* detector_name;
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

struct PortNode
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

class PatternClientDetector : public ClientDetector
{
public:
    PatternClientDetector(ClientDiscovery*);
    ~PatternClientDetector() override;

    void insert_client_port_pattern(PortPatternNode*);
    void finalize_client_port_patterns(AppIdInspector&);
    void reload_client_port_patterns();
    unsigned get_pattern_count();

    int validate(AppIdDiscoveryArgs&) override;

private:
    void create_client_pattern_trees();
    void register_client_patterns();

    PortPatternNode* lua_injected_patterns = nullptr;
    PatternService* service_port_pattern = nullptr;
    snort::SearchTool* tcp_pattern_matcher = nullptr;
    snort::SearchTool* udp_pattern_matcher = nullptr;
    unsigned pattern_count = 0;
};

class PatternServiceDetector : public ServiceDetector
{
public:
    PatternServiceDetector(ServiceDiscovery*);
    ~PatternServiceDetector() override;

    void insert_service_port_pattern(PortPatternNode*);
    void finalize_service_port_patterns(AppIdInspector&);
    void reload_service_port_patterns();
    unsigned get_pattern_count();

    int validate(AppIdDiscoveryArgs&) override;

private:
    void create_service_pattern_trees();
    void register_service_patterns();
    void install_ports(PatternService*);

    PortPatternNode* lua_injected_patterns = nullptr;
    PatternService* service_port_pattern = nullptr;
    snort::SearchTool* tcp_pattern_matcher = nullptr;
    snort::SearchTool* udp_pattern_matcher = nullptr;
    snort::SearchTool* tcp_port_pattern_tree[65536] = { };
    snort::SearchTool* udp_port_pattern_tree[65536] = { };
    unsigned pattern_count = 0;
};

#endif

