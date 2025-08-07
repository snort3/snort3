//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// service_plugins_mock.h author Kani Murthi <kamurthi@cisco.com>

#ifndef SERVICE_PLUGIN_MOCK_H
#define SERVICE_PLUGIN_MOCK_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <framework/data_bus.h>
#include <detection/detection_engine.h>
#include <appid/appid_inspector.h>
#include <appid/service_plugins/service_discovery.h>

#include "appid_detector.h"
#include "appid_module.h"
#include "appid_peg_counts.h"

#define APPID_UT_ID 1492

namespace snort
{
// Stubs for messages
void ParseWarning(WarningGroup, const char*, ...) { }

// Stubs for appid sessions
FlowData::FlowData(unsigned, Inspector*) : handler(nullptr), id(0)
{ }
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
SearchTool::SearchTool(bool, const char*) { }
SearchTool::~SearchTool() = default;

// Stubs for util.cc
char* snort_strndup(const char* , size_t dst_size)
{
    char* dup = (char*)snort_calloc(dst_size + 1);
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
void snort::Module::sum_stats(bool) {}
void snort::Module::show_interval_stats(std::vector<unsigned>&, FILE*) {}
void snort::Module::show_stats() {}
void snort::Module::init_stats(bool) {}
void snort::Module::reset_stats() {}
void snort::Module::main_accumulate_stats() {}

AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&)
{ }
}

AlpnPatternMatchers::~AlpnPatternMatchers() {}
EveCaPatternMatchers::~EveCaPatternMatchers() { }
HostPatternMatchers::~HostPatternMatchers() { }
SipPatternMatchers::~SipPatternMatchers() { }
HttpPatternMatchers::~HttpPatternMatchers() { }
DnsPatternMatchers::~DnsPatternMatchers() { }
UserDataMap::~UserDataMap() { }
CipPatternMatchers::~CipPatternMatchers() { }
void ClientDiscovery::initialize(AppIdInspector&) {}
void ClientDiscovery::reload() {}

int AppIdDetector::initialize(AppIdInspector&){return 0;}
int AppIdDetector::data_add(AppIdSession&, AppIdFlowData*){return 0;}
AppIdFlowData* AppIdDetector::data_get(const AppIdSession&) {return nullptr;}
void AppIdDetector::add_user(AppIdSession&, const char*, AppId, bool, AppidChangeBits&){}
void AppIdDetector::add_payload(AppIdSession&, AppId){}
void AppIdDetector::add_app(const snort::Packet&, AppIdSession&, AppidSessionDirection, AppId, AppId, const char*, AppidChangeBits&){}
void ApplicationDescriptor::set_id(AppId){}
void ServiceAppDescriptor::set_id(AppId, OdpContext&){}
void ClientAppDescriptor::update_user(AppId, const char*, AppidChangeBits&){}
void AppIdDiscovery::add_pattern_data(AppIdDetector*, snort::SearchTool&, int,
        const uint8_t* const, unsigned, unsigned){}
void AppIdDiscovery::register_detector(const std::string&, AppIdDetector*,  IpProtocol){}
void AppIdDiscovery::register_tcp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned){}
void AppIdDiscovery::register_udp_pattern(AppIdDetector*, const uint8_t* const, unsigned,
    int, unsigned){}
int AppIdDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&){return 0;}
void ApplicationDescriptor::set_id(const snort::Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&){}
int dcerpc_validate(const uint8_t*, int){return 0; }
AppIdDiscovery::~AppIdDiscovery() { }
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
AppIdConfig config;
AppIdContext ctxt(config);
ServiceDetector::ServiceDetector() {}
int ServiceDetector::incompatible_data(AppIdSession& asd, const snort::Packet* pkt, AppidSessionDirection dir) { return 0; }
int ServiceDetector::fail_service(AppIdSession& asd, const snort::Packet* pkt, AppidSessionDirection dir) { return 0; }
int ServiceDetector::service_inprocess(AppIdSession& asd, const snort::Packet* pkt, AppidSessionDirection dir) { return 0; }
int ServiceDetector::add_service_consume_subtype(AppIdSession& asd, const snort::Packet* pkt,
    AppidSessionDirection dir, AppId appId, const char* vendor, const char* version,
    AppIdServiceSubtype* subtype, AppidChangeBits& change_bits)
    { return 0; }
int ServiceDetector::add_service(AppidChangeBits& change_bits, AppIdSession& asd,
    const snort::Packet* pkt, AppidSessionDirection dir, AppId appId, const char* vendor,
    const char* version, AppIdServiceSubtype* subtype)
    { return 0; }
void ServiceDetector::register_appid(AppId appId, unsigned extractsInfo, OdpContext& odp_ctxt) {}

void AppIdDebug::activate(const snort::Flow*, const AppIdSession*, bool) { active = false; }

AppIdSession* AppIdSession::create_future_session(const snort::Packet* ctrlPkt, const snort::SfIp* cliIp,
    uint16_t cliPort, const snort::SfIp* srvIp, uint16_t srvPort, IpProtocol proto,
    SnortProtocolId snort_protocol_id, OdpContext& odp_ctxt, bool swap_app_direction,
    bool bidirectional, bool expect_persist) { return nullptr; }
void AppIdSession::initialize_future_session(AppIdSession& expected, uint64_t flags) {}

// Stubs for modules, config
AppIdConfig::~AppIdConfig() = default;
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

void AppIdModule::set_trace(const snort::Trace*) const { }
const snort::TraceOption* AppIdModule::get_trace_options() const { return nullptr; }

// Stubs for inspectors
unsigned AppIdSession::inspector_id = 0;
AppIdConfig stub_config;
AppIdContext stub_ctxt(stub_config);
static OdpContext stub_odp_ctxt(stub_config, nullptr);
OdpContext* AppIdContext::odp_ctxt = &stub_odp_ctxt;
AppIdSession::AppIdSession(IpProtocol, const snort::SfIp* ip, uint16_t, AppIdInspector& inspector,
    OdpContext& odpctxt, uint32_t
#ifndef DISABLE_TENANT_ID
    ,uint32_t
#endif
    ) : snort::FlowData(inspector_id, (snort::Inspector*)&inspector),
        config(stub_config), api(*(new snort::AppIdSessionApi(this, *ip))), odp_ctxt(odpctxt)
{ }
AppIdSession::~AppIdSession() = default;
DiscoveryFilter::~DiscoveryFilter(){}
void AppIdSession::free_flow_data()
{
    
}
AppIdFlowData* AppIdSession::get_flow_data(unsigned) const
{
    return nullptr;
}

// Stubs for AppIdPegCounts
//void AppIdPegCounts::inc_service_count(AppId, bool) { }
//void AppIdPegCounts::inc_client_count(AppId, bool) { }
//void AppIdPegCounts::inc_payload_count(AppId, bool) { }

THREAD_LOCAL AppIdStats appid_stats;
void AppIdModule::show_dynamic_stats() { }

// Stubs for app_info_table.cc
AppInfoTableEntry* AppInfoManager::get_app_info_entry(int)
{
    return nullptr;
}

bool AppInfoManager::configured()
{
    return true;
}


void ServiceDiscovery::initialize(AppIdInspector&) {}
void ServiceDiscovery::reload() {}
int ServiceDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&) { return 0; }

OdpContext::OdpContext(const AppIdConfig&, snort::SnortConfig*)
{ }

void appid_log(const snort::Packet*, unsigned char, char const*, ...) { }
int AppIdSession::add_flow_data_id(uint16_t, ServiceDetector*) { return 0; }
AppIdHttpSession* AppIdSession::get_http_session(uint32_t) const { return nullptr; }
AppIdHttpSession* AppIdSession::create_http_session(int64_t stream_id) { return nullptr; }
void AppIdHttpSession::set_field(HttpFieldIds id, const std::string* str, AppidChangeBits&) { }

void snort::DataBus::publish(unsigned, unsigned, snort::DataEvent&, snort::Flow*) { }
void snort::DataBus::publish(unsigned, unsigned, const uint8_t*, unsigned, snort::Flow*) { }
void snort::DataBus::publish(unsigned, unsigned, snort::Packet*, snort::Flow*) { }

snort::Packet* snort::DetectionEngine::get_current_packet() { return nullptr; }

unsigned AppIdInspector::get_pub_id() { return 0; }
#endif
