//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "appid_inspector.h"

class Value;

namespace snort
{
Inspector::Inspector() : ref_count(nullptr)
{
    set_api(nullptr);
}

Inspector::~Inspector() = default;
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

Module::Module(char const*, char const*) {}
void Module::sum_stats(bool) {}
void Module::main_accumulate_stats() { }
void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*) {}
void Module::show_stats() {}
void Module::init_stats(bool) {}
void Module::reset_stats() {}
PegCount Module::get_global_count(char const*) const { return 0; }

}

AppIdModule::AppIdModule(): snort::Module("appid_mock", "appid_mock_help") {}
void AppIdModule::sum_stats(bool) {}
void AppIdModule::show_dynamic_stats() {}
bool AppIdModule::begin(char const*, int, snort::SnortConfig*) { return true; }
bool AppIdModule::end(char const*, int, snort::SnortConfig*) { return true; }
bool AppIdModule::set(char const*, snort::Value&, snort::SnortConfig*) { return true; }
const snort::Command* AppIdModule::get_commands() const { return nullptr; }
const PegInfo* AppIdModule::get_pegs() const { return nullptr; }
PegCount* AppIdModule::get_counts() const { return nullptr; }
snort::ProfileStats* AppIdModule::get_profile(
        unsigned, const char*&, const char*& ) const { return nullptr; }
void AppIdModule::set_trace(const Trace*) const { }
const TraceOption* AppIdModule::get_trace_options() const { return nullptr; }

AppIdInspector::~AppIdInspector() = default;
void AppIdInspector::eval(snort::Packet*) { }
bool AppIdInspector::configure(snort::SnortConfig*) { return true; }
void AppIdInspector::show(const SnortConfig*) const { }
void AppIdInspector::tinit() { }
void AppIdInspector::tterm() { }
void AppIdInspector::tear_down(snort::SnortConfig*) { }
AppIdContext& AppIdInspector::get_ctxt() const { return *ctxt; }

AppIdModule appid_mod;
AppIdConfig appid_config;
AppIdContext appid_ctxt(appid_config);
THREAD_LOCAL OdpContext* pkt_thread_odp_ctxt = nullptr;
AppIdInspector dummy_appid_inspector( appid_mod );

AppIdInspector::AppIdInspector(AppIdModule& )
{
    ctxt = &appid_ctxt;
    appid_config.app_detector_dir = "/path/to/appid/detectors/";
    config = &appid_config;
}

#endif
