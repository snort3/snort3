//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

Inspector::Inspector()
{
    set_api(nullptr);
}

Inspector::~Inspector() { }
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return true; }
class StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

Module::Module(const char*, const char*) { }
void Module::sum_stats(bool ) {}
void Module::show_interval_stats(IndexVec&, FILE*) {}
void Module::show_stats() {}
void Module::reset_stats() {}

AppIdModule::~AppIdModule() {}
AppIdModule::AppIdModule() : Module(nullptr, nullptr), config(nullptr) {}
bool AppIdModule::begin(char const*, int, SnortConfig*) { return true; }
bool AppIdModule::end(char const*, int, SnortConfig*) { return true; }
bool AppIdModule::set(char const*, Value&, SnortConfig*) { return true; }
const PegInfo* AppIdModule::get_pegs() const { return nullptr; }
PegCount* AppIdModule::get_counts() const { return nullptr; }
ProfileStats* AppIdModule::get_profile() const { return nullptr; }

AppIdInspector::AppIdInspector(AppIdModule& m) : appid_mod(m), my_seh(nullptr) { }
AppIdInspector::~AppIdInspector() { }
AppIdInspector* AppIdInspector::get_inspector() { AppIdModule aim; return new AppIdInspector(aim); }
void AppIdInspector::eval(Packet*) { }
int16_t AppIdInspector::add_appid_protocol_reference(char const*) { return 1066; }
bool AppIdInspector::configure(SnortConfig*) { return true; }
void AppIdInspector::show(SnortConfig*) { }
void AppIdInspector::tinit() { }
void AppIdInspector::tterm() { }
