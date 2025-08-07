//--------------------------------------------------------------------------
// Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
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
// detector_plugins_mock.h author Masud Hasan <mashasan@cisco.com>

#ifndef DETECTOR_PLUGINS_MOCK_H
#define DETECTOR_PLUGINS_MOCK_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <utils/util_cstring.h>
#include <framework/module.h>
#include <appid/service_plugins/service_detector.h>
#include <appid/client_plugins/client_detector.h>
#include <appid/appid_inspector.h>

#include "log/messages.h"
#include "utils/stats.h"

#include "appid_detector.h"
#include "appid_module.h"
#include "appid_peg_counts.h"

namespace snort
{
// Stubs for messages
// LCOV_EXCL_START
void ParseWarning(WarningGroup, const char*, ...) { }
// LCOV_EXCL_STOP

// Stubs for appid sessions
FlowData::FlowData(unsigned, Inspector*) : handler(nullptr), id(0)
{ }
FlowData::~FlowData() = default;
FlowDataStore::~FlowDataStore() = default;

// Stubs for packet
Packet::Packet(bool) { }
Packet::~Packet() = default;

Inspector::Inspector() = default;
Inspector::~Inspector() = default;
// LCOV_EXCL_START
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
// LCOV_EXCL_STOP

// Stubs for search_tool.cc
SearchTool::~SearchTool() = default;
// LCOV_EXCL_START
void SearchTool::add(const char*, unsigned, int, bool, bool) { }
void SearchTool::add(const char*, unsigned, void*, bool, bool) { }
void SearchTool::add(const uint8_t*, unsigned, int, bool, bool) { }
void SearchTool::add(const uint8_t*, unsigned, void*, bool, bool) { }
// LCOV_EXCL_STOP
void SearchTool::prep() { }

// Stubs for util.cc
char* snort_strndup(const char* src, size_t dst_size)
{
    char* dup = (char*)snort_calloc(dst_size + 1);
    if ( SnortStrncpy(dup, src, dst_size + 1) == SNORT_STRNCPY_ERROR )
    {
        snort_free(dup);
        return nullptr;
    }
    return dup;
}

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}
}
// LCOV_EXCL_START
DiscoveryFilter::~DiscoveryFilter(){}
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }
// LCOV_EXCL_STOP

// Stubs for modules, config
AppIdConfig::~AppIdConfig() = default;
AppIdModule::AppIdModule()
    : Module("a", "b") { }
AppIdModule::~AppIdModule() = default;

// LCOV_EXCL_START
bool AppIdModule::begin(const char*, int, snort::SnortConfig*)
{
    return false;
}

bool AppIdModule::set(const char*, snort::Value&, snort::SnortConfig*)
{
    return false;
}

bool AppIdModule::end(const char*, int, snort::SnortConfig*)
{
    return false;
}

const snort::Command* AppIdModule::get_commands() const
{
    return nullptr;
}

const PegInfo* AppIdModule::get_pegs() const
{
    return nullptr;
}

PegCount* AppIdModule::get_counts() const
{
    return nullptr;
}

snort::ProfileStats* AppIdModule::get_profile(
        unsigned, const char*&, const char*&) const
{
    return nullptr;
}

void AppIdModule::set_trace(const snort::Trace*) const { }
const snort::TraceOption* AppIdModule::get_trace_options() const { return nullptr; }
// LCOV_EXCL_STOP

// Stubs for inspectors
unsigned AppIdSession::inspector_id = 0;
AppIdConfig stub_config;
AppIdContext stub_ctxt(stub_config);
OdpContext stub_odp_ctxt(stub_config, nullptr);
AppIdSession::AppIdSession(IpProtocol, const snort::SfIp* ip, uint16_t, AppIdInspector& inspector,
    OdpContext& odpctxt, uint32_t
#ifndef DISABLE_TENANT_ID
    ,uint32_t
#endif
    ) : snort::FlowData(inspector_id, (snort::Inspector*)&inspector),
        config(stub_config), api(*(new snort::AppIdSessionApi(this, *ip))), odp_ctxt(odpctxt)
{
    
}
AppIdSession::~AppIdSession() { delete &api; }
AppIdHttpSession::AppIdHttpSession(AppIdSession& asd, int64_t http2_stream_id)
  : asd(asd), httpx_stream_id(http2_stream_id)
{
    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
        meta_data[i] = nullptr;
}

AppIdHttpSession::~AppIdHttpSession()
{
    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
    {
        if ( meta_data[i] )
            delete meta_data[i];
    }
}

// Stubs for AppIdPegCounts
// LCOV_EXCL_START
void AppIdPegCounts::inc_service_count(AppId) { }
void AppIdPegCounts::inc_client_count(AppId) { }
void AppIdPegCounts::inc_user_count(AppId) { }
void AppIdPegCounts::inc_payload_count(AppId) { }

THREAD_LOCAL AppIdStats appid_stats;
void AppIdModule::sum_stats(bool) { }
void AppIdModule::show_dynamic_stats() { }

// Stubs for appid_session.cc
static bool test_service_strstr_enabled = false;
const uint8_t* service_strstr(const uint8_t* p, unsigned,
    const uint8_t*, unsigned)
{
    if (test_service_strstr_enabled)
        return p;
    return nullptr;
}

// Stubs for app_info_table.cc
AppInfoTableEntry* AppInfoManager::get_app_info_entry(int)
{
    return nullptr;
}

AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId, const AppInfoTable&)
{
    return nullptr;
}

bool AppIdReloadTuner::tinit() { return false; }

bool AppIdReloadTuner::tune_resources(unsigned int)
{
    return true;
}
void ApplicationDescriptor::set_id(AppId){}
void ServiceAppDescriptor::set_id(AppId, OdpContext&){}
void ServiceDiscovery::initialize(AppIdInspector&) {}
void ServiceDiscovery::reload() {}

int ServiceDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&)
{ return 0; }
// LCOV_EXCL_STOP

OdpContext::OdpContext(const AppIdConfig&, snort::SnortConfig*)
{ }

THREAD_LOCAL OdpContext* pkt_thread_odp_ctxt = nullptr;

// Stubs for module
snort::Module::Module(char const*, char const*) {}
void snort::Module::sum_stats(bool) {}
void snort::Module::show_interval_stats(std::vector<unsigned>&, FILE*) {}
void snort::Module::show_stats() {}
void snort::Module::init_stats(bool) {}
void snort::Module::reset_stats() {}
void snort::Module::main_accumulate_stats() {}
PegCount snort::Module::get_global_count(char const*) const { return 0; }


void ApplicationDescriptor::set_id(const snort::Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }
AppIdDiscovery::~AppIdDiscovery() = default;
void ClientDiscovery::initialize(AppIdInspector&) { }
void ClientDiscovery::reload() { }
void AppIdDiscovery::register_detector(const string&, AppIdDetector*, IpProtocol) { }
void AppIdDiscovery::add_pattern_data(AppIdDetector*, snort::SearchTool&, int, unsigned char const*, unsigned int, unsigned int) { }
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, unsigned char const*, unsigned int, int, unsigned int) { }
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, unsigned char const*, unsigned int, int, unsigned int) { }
int AppIdDiscovery::add_service_port(AppIdDetector*, ServiceDetectorPort const&) { return 0; }
DnsPatternMatchers::~DnsPatternMatchers() = default;
EveCaPatternMatchers::~EveCaPatternMatchers() = default;
#ifndef SIP_UNIT_TEST
SipPatternMatchers::~SipPatternMatchers() = default;
#endif
HostPatternMatchers::~HostPatternMatchers() = default;
AlpnPatternMatchers::~AlpnPatternMatchers() = default;
#ifndef HTTP_PATTERNS_UNIT_TEST
HttpPatternMatchers::~HttpPatternMatchers() = default;
#endif
UserDataMap::~UserDataMap() = default;
CipPatternMatchers::~CipPatternMatchers() = default;
bool HostPatternMatchers::scan_url(const uint8_t*, size_t, AppId&, AppId&, bool*){ return true; }   
void AppIdModule::reset_stats() {}
bool AppIdInspector::configure(snort::SnortConfig*) { return true; }
void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }
void HostPatternMatchers::add_host_pattern(unsigned char const*, unsigned long, unsigned char, int, int, HostPatternType, bool, bool) {}

#ifndef SIP_UNIT_TEST
snort::SearchTool::SearchTool(bool, const char*) { }
#endif

ServiceDetector::ServiceDetector() {}
void ServiceDetector::register_appid(AppId appId, unsigned extractsInfo, OdpContext& odp_ctxt) {}
int ServiceDetector::add_service_consume_subtype(AppIdSession& asd, const snort::Packet* pkt,
    AppidSessionDirection dir, AppId appId, const char* vendor, const char* version,
    AppIdServiceSubtype* subtype, AppidChangeBits& change_bits)
    { return 0; }
int ServiceDetector::add_service(AppidChangeBits& change_bits, AppIdSession& asd,
    const snort::Packet* pkt, AppidSessionDirection dir, AppId appId, const char* vendor,
    const char* version, AppIdServiceSubtype* subtype)
    { return 0; }
int ServiceDetector::service_inprocess(AppIdSession& asd, const snort::Packet* pkt, AppidSessionDirection dir) { return 0; }

snort::AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&)
{ }

AppIdInspector::~AppIdInspector() = default;

void ClientDetector::register_appid(int, unsigned int, OdpContext&) { }

void AppIdInspector::eval(snort::Packet*) { }
void AppIdInspector::show(const snort::SnortConfig*) const { }
void AppIdInspector::tinit() { }
void AppIdInspector::tterm() { }
void AppIdInspector::tear_down(snort::SnortConfig*) { }

ClientDetector::ClientDetector() { }

void AppIdSession::set_client_appid_data(AppId, AppidChangeBits&, char*) { }
int AppIdSession::add_flow_data_id(uint16_t, ServiceDetector*) { return 0; }
#endif
