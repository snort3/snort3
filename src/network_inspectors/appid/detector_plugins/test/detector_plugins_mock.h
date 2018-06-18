//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

namespace snort
{
// Stubs for messages
void ErrorMessage(const char*,...) { }
void WarningMessage(const char*,...) { }
void LogMessage(const char*,...) { }
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
void SearchTool::add(const char*, unsigned, int, bool) { }
void SearchTool::add(const char*, unsigned, void*, bool) { }
void SearchTool::add(const uint8_t*, unsigned, int, bool) { }
void SearchTool::add(const uint8_t*, unsigned, void*, bool) { }
void SearchTool::prep() { }
static bool test_find_all_done = false;
static bool test_find_all_enabled = false;
static MatchedPatterns* mock_mp = nullptr;
int SearchTool::find_all(const char*, unsigned, MpseMatch, bool, void* mp_arg)
{
    test_find_all_done = true;
    if (test_find_all_enabled)
        memcpy(mp_arg, &mock_mp, sizeof(MatchedPatterns*));
    return 0;
}

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

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

class AppIdInspector : public snort::Inspector
{
public:
    AppIdInspector(AppIdModule&) { }
    ~AppIdInspector() override = default;
    void eval(Packet*) override { }
    bool configure(snort::SnortConfig*) override { return true; }
    void show(snort::SnortConfig*) override { }
    void tinit() override { }
    void tterm() override { }
};

// Stubs for modules, config
AppIdModuleConfig::~AppIdModuleConfig() = default;
AppIdModule::AppIdModule()
    : Module("a", "b") { }
AppIdModule::~AppIdModule() = default;
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

// Stubs for inspectors
unsigned AppIdSession::inspector_id = 0;
AppIdSession::AppIdSession(IpProtocol, const SfIp*, uint16_t, AppIdInspector& inspector)
    : snort::FlowData(inspector_id, (snort::Inspector*)&inspector), inspector(inspector) { }
AppIdSession::~AppIdSession() = default;
AppIdHttpSession::AppIdHttpSession(AppIdSession& asd)
    : asd(asd)
{
    http_matchers = HttpPatternMatchers::get_instance();

    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
        meta_data[i] = nullptr;
}

AppIdHttpSession::~AppIdHttpSession()
{
    delete xff_addr;

    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
    {
        if ( meta_data[i] )
            delete meta_data[i];
    }
}

// Stubs for AppIdPegCounts
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

// Stubs for appid_http_session.cc
static bool test_field_offset_set_done = false;

// Stubs for app_info_table.cc
AppInfoTableEntry* AppInfoManager::get_app_info_entry(int)
{
    return nullptr;
}

AppInfoTableEntry* AppInfoManager::get_app_info_entry(AppId, const AppInfoTable&)
{
    return nullptr;
}

#endif

