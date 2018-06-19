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

// appid_mock_inspector.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_MOCK_INSPECTOR_H
#define APPID_MOCK_INSPECTOR_H

typedef uint64_t Trace;
class Value;

namespace snort
{
Inspector::Inspector()
{
    set_api(nullptr);
}

Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

Module::Module(char const*, char const*) {}
bool Module::set(const char*, Value&, SnortConfig*) { return true; }
void Module::sum_stats(bool) {}
void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*) {}
void Module::show_stats() {}
void Module::reset_stats() {}
PegCount Module::get_global_count(char const*) const { return 0; }

}

AppIdModule::AppIdModule(): snort::Module("appid_mock", "appid_mock_help") {}
AppIdModule::~AppIdModule() {}
void AppIdModule::sum_stats(bool) {}
void AppIdModule::show_dynamic_stats() {}
bool AppIdModule::begin(char const*, int, snort::SnortConfig*) { return true; }
bool AppIdModule::end(char const*, int, snort::SnortConfig*) { return true; }
bool AppIdModule::set(char const*, snort::Value&, snort::SnortConfig*) { return true; }
const snort::Command* AppIdModule::get_commands() const { return nullptr; }
const PegInfo* AppIdModule::get_pegs() const { return nullptr; }
PegCount* AppIdModule::get_counts() const { return nullptr; }
snort::ProfileStats* AppIdModule::get_profile() const { return nullptr; }

class AppIdInspector : public snort::Inspector
{
public:
    AppIdInspector(AppIdModule& ) { }
    ~AppIdInspector() override = default;
    void eval(snort::Packet*) override { }
    bool configure(snort::SnortConfig*) override { return true; }
    void show(snort::SnortConfig*) override { }
    void tinit() override { }
    void tterm() override { }
};

AppIdModule appid_mod;
AppIdInspector appid_inspector( appid_mod );

#endif
