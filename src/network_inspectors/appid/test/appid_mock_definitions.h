//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "service_inspectors/http_inspect/http_msg_header.h"

class Inspector;
struct ThirdPartyAppIDModule;

AppIdConfig* pAppidActiveConfig = nullptr;
ThirdPartyAppIDModule* tp_appid_module = nullptr;

namespace snort
{
char* snort_strndup(const char* src, size_t dst_size)
{
    return strndup(src, dst_size);
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
void ParseWarning(WarningGroup, const char*, ...) { }

void LogLabel(const char*, FILE*) {}
}

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

// Stubs for app_info_table.h
AppInfoTableEntry* AppInfoManager::get_app_info_entry(int)
{
  return nullptr;
}

bool AppInfoManager::configured()
{ return false; }

// Stubs for service_state.h
ServiceDiscoveryState* AppIdServiceState::get(SfIp const*, IpProtocol, unsigned short, bool)
{
  return nullptr;
}

ServiceDiscoveryState* AppIdServiceState::add(SfIp const*, IpProtocol, unsigned short, bool)
{
  return nullptr;
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

void mock_init_appid_pegs()
{
    AppIdPegCounts::init_pegs();
}

void mock_cleanup_appid_pegs()
{
    AppIdPegCounts::cleanup_pegs();
    AppIdPegCounts::cleanup_peg_info();
}

THREAD_LOCAL AppIdStats appid_stats;

#endif

