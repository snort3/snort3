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
}

class AppIdModule
{
public:
    AppIdModule() = default;
    ~AppIdModule() = default;

};

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
