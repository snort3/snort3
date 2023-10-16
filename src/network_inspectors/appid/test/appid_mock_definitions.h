//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// appid_mock_definitions.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_MOCK_DEFINITIONS_H
#define APPID_MOCK_DEFINITIONS_H

#include "appid_detector.h"
#include "appid_module.h"
#include "appid_peg_counts.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "utils/stats.h"

class ThirdPartyAppIdContext;

ThirdPartyAppIdContext* tp_appid_ctxt = nullptr;

namespace snort
{
char* snort_strndup(const char* src, size_t dst_size)
{
    char* dup = (char*)snort_calloc(dst_size + 1);
    strncpy(dup, src, dst_size + 1);
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

void ErrorMessage(const char*,...) { }
void WarningMessage(const char*,...) { }
void LogMessage(const char*,...) { }
void LogText(const char*, FILE*) {}

void ParseWarning(WarningGroup, const char*, ...) { }
void LogLabel(const char*, FILE*) {}

unsigned DataBus::get_id(const PubKey&) { return 0; }

SearchTool::SearchTool(bool) { }
SearchTool::~SearchTool() = default;
}
DiscoveryFilter::~DiscoveryFilter(){}
void ApplicationDescriptor::set_id(AppId app_id){ my_id = app_id;}
void ServiceAppDescriptor::set_id(AppId app_id, OdpContext&){ set_id(app_id); }
void ServiceAppDescriptor::set_port_service_id(AppId app_id){ port_service_id = app_id;}
void ClientAppDescriptor::update_user(AppId app_id, const char* username, AppidChangeBits& change_bits)
{
    my_username = username;
    my_user_id = app_id;
    change_bits.set(APPID_USER_INFO_BIT);
}

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
HttpPatternMatchers::~HttpPatternMatchers() = default;
SipPatternMatchers::~SipPatternMatchers() = default;
SslPatternMatchers::~SslPatternMatchers() = default;
AlpnPatternMatchers::~AlpnPatternMatchers() = default;
CipPatternMatchers::~CipPatternMatchers() = default;

void Field::set(int32_t length, const uint8_t* start, bool own_the_buffer_)
{
    strt = start;
    len = length;
    own_the_buffer = own_the_buffer_;
}

Field global_field;


int ServiceDiscovery::add_ftp_service_state(AppIdSession&)
{
    return 0;
}

void ServiceDiscovery::initialize(AppIdInspector&) { }
void ServiceDiscovery::reload() { }

int ServiceDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&)
{ return 0; }

// Stubs for app_info_table.h
AppInfoTableEntry* AppInfoManager::get_app_info_entry(int)
{
  return nullptr;
}

bool AppInfoManager::configured()
{ return false; }

// Stubs for service_state.h
ServiceDiscoveryState* AppIdServiceState::get(SfIp const*, IpProtocol,
    unsigned short, int16_t, uint32_t, bool, bool)
{
  return nullptr;
}

ServiceDiscoveryState* AppIdServiceState::add(SfIp const*, IpProtocol,
    unsigned short, int16_t, uint32_t, bool, bool)
{
  return nullptr;
}

bool AppIdServiceState::prune(size_t, size_t)
{
    return true;
}

bool AppIdReloadTuner::tinit() { return false; }

bool AppIdReloadTuner::tune_resources(unsigned int)
{
    return true;
}

void ServiceDiscoveryState::set_service_id_valid(ServiceDetector*) { }

// Stubs for service_plugins/service_discovery.h
int ServiceDiscovery::incompatible_data(AppIdSession&, const Packet*, AppidSessionDirection, ServiceDetector*)
{
    return 0;
}

int ServiceDiscovery::fail_service(AppIdSession&, const Packet*, AppidSessionDirection, ServiceDetector*, ServiceDiscoveryState*)
{
    return 0;
}

inline void mock_init_appid_pegs()
{
    AppIdPegCounts::init_pegs();
}

inline void mock_cleanup_appid_pegs()
{
    AppIdPegCounts::cleanup_pegs();
    AppIdPegCounts::cleanup_peg_info();
}

THREAD_LOCAL AppIdStats appid_stats;

#endif
