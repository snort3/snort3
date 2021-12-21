//--------------------------------------------------------------------------
// Copyright (C) 2018-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "appid_detector.h"
#include "appid_module.h"
#include "appid_peg_counts.h"
#include "utils/stats.h"

namespace snort
{
// Stubs for messages
void ErrorMessage(const char*,...) { }
// LCOV_EXCL_START
void WarningMessage(const char*,...) { }
void LogMessage(const char*,...) { }
void ParseWarning(WarningGroup, const char*, ...) { }
// LCOV_EXCL_STOP

// Stubs for appid sessions
FlowData::FlowData(unsigned, Inspector*) { }
FlowData::~FlowData() = default;

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
void SearchTool::add(const char*, unsigned, int, bool) { }
void SearchTool::add(const char*, unsigned, void*, bool) { }
void SearchTool::add(const uint8_t*, unsigned, int, bool) { }
void SearchTool::add(const uint8_t*, unsigned, void*, bool) { }
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
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }
// LCOV_EXCL_STOP

#ifndef SIP_UNIT_TEST
class AppIdInspector : public snort::Inspector
{
public:
    AppIdInspector(AppIdModule&) { }
    ~AppIdInspector() override = default;
    bool configure(snort::SnortConfig*) override;
// LCOV_EXCL_START
    void eval(Packet*) override { }
    void show(const SnortConfig*) const override { }
    void tinit() override { }
    void tterm() override { }
// LCOV_EXCL_STOP
private:
    AppIdContext* ctxt = nullptr;
};
#endif

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

const Command* AppIdModule::get_commands() const
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

snort::ProfileStats* AppIdModule::get_profile() const
{
    return nullptr;
}

void AppIdModule::set_trace(const Trace*) const { }
const TraceOption* AppIdModule::get_trace_options() const { return nullptr; }
// LCOV_EXCL_STOP

// Stubs for inspectors
unsigned AppIdSession::inspector_id = 0;
AppIdConfig stub_config;
AppIdContext stub_ctxt(stub_config);
OdpContext stub_odp_ctxt(stub_config, nullptr);
AppIdSession::AppIdSession(IpProtocol, const SfIp* ip, uint16_t, AppIdInspector& inspector,
    OdpContext& odpctxt, uint16_t) : snort::FlowData(inspector_id, (snort::Inspector*)&inspector),
        config(stub_config), api(*(new AppIdSessionApi(this, *ip))), odp_ctxt(odpctxt)
{
    this->set_session_flags(APPID_SESSION_DISCOVER_APP);
}
AppIdSession::~AppIdSession() { delete &api; }
AppIdHttpSession::AppIdHttpSession(AppIdSession& asd, uint32_t http2_stream_id)
  : asd(asd), http2_stream_id(http2_stream_id)
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
#endif
