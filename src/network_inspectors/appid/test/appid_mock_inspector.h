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

AppIdInspector::AppIdInspector(const AppIdModuleConfig*) { }
AppIdInspector::~AppIdInspector() { }
AppIdInspector* AppIdInspector::get_inspector() { return new AppIdInspector(nullptr); }
void AppIdInspector::eval(Packet*) { }
int16_t AppIdInspector::add_appid_protocol_reference(char const*) { return 1066; }
bool AppIdInspector::configure(SnortConfig*) { return true; }
void AppIdInspector::show(SnortConfig*) { }
void AppIdInspector::tinit() { }
void AppIdInspector::tterm() { }

