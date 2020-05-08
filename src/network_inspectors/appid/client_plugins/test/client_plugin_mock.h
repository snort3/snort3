//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// client_plugins_mock.h author Kani Murthi <kamurthi@cisco.com>

#ifndef CLIENT_PLUGIN_MOCK_H
#define CLIENT_PLUGIN_MOCK_H

#include "appid_detector.h"
#include "appid_module.h"
#include "appid_peg_counts.h"
#include "utils/stats.h"
namespace snort
{
// Stubs for messages
void ParseWarning(WarningGroup, const char*, ...) { }

// Stubs for appid sessions
FlowData::FlowData(unsigned, Inspector*) { }
FlowData::~FlowData() = default;

// Stubs for packet
Packet::Packet(bool) { }
Packet::~Packet() = default;

Inspector::Inspector() = default;
Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

// Stubs for search_tool.cc
SearchTool::SearchTool(const char*, bool) { }
SearchTool::~SearchTool() = default;

// Stubs for util.cc
char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}
class InspectorManager
{
public:
    SO_PUBLIC static Inspector* get_inspector(const char*, bool, SnortConfig*) {return nullptr;}
};
PegCount Module::get_global_count(char const*) const { return 0; }
void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*) {}
void Module::show_stats(){}
void Module::sum_stats(bool ){}
void Module::reset_stats() {}
}

SslPatternMatchers::~SslPatternMatchers() { }
SipPatternMatchers::~SipPatternMatchers() { }
HttpPatternMatchers::~HttpPatternMatchers() { }
DnsPatternMatchers::~DnsPatternMatchers() { }
void ClientDiscovery::initialize() {}

int AppIdDetector::initialize(){return 0;}
int AppIdDetector::data_add(AppIdSession&, void*, AppIdFreeFCN){return 0;}
void* AppIdDetector::data_get(AppIdSession&) {return nullptr;}
void AppIdDetector::add_user(AppIdSession&, const char*, AppId, bool){}
void AppIdDetector::add_payload(AppIdSession&, AppId){}
void AppIdDetector::add_app(const snort::Packet&, AppIdSession&, AppidSessionDirection, AppId, AppId, const char*, AppidChangeBits&){}
void AppIdDiscovery::add_pattern_data(AppIdDetector*, snort::SearchTool*, int,
        const uint8_t* const, unsigned, unsigned){}
void AppIdDiscovery::register_detector(const std::string&, AppIdDetector*,  IpProtocol){}
void add_pattern_data(AppIdDetector*, snort::SearchTool*, int,
    const uint8_t* const, unsigned, unsigned) {}
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned){}
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned){}
int AppIdDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&){return 0;}
void ApplicationDescriptor::set_id(const snort::Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&){}
void ApplicationDescriptor::set_id(AppId){}
AppIdDiscovery::AppIdDiscovery() { }
AppIdDiscovery::~AppIdDiscovery() { }
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }
AppIdConfig config;
AppIdContext ctxt(config);

// Stubs for modules, config
AppIdConfig::~AppIdConfig() = default;

// Stubs for AppIdPegCounts
void AppIdPegCounts::inc_payload_count(AppId) { }
void AppIdPegCounts::inc_client_count(AppId) { }

THREAD_LOCAL AppIdStats appid_stats;

// Stubs for app_info_table.cc
AppInfoTableEntry* AppInfoManager::get_app_info_entry(int)
{
    return nullptr;
}

bool AppInfoManager::configured()
{
    return true;
}

#endif
