//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// client_plugins_mock.h author author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#define APPID_UT_ID 1492

namespace snort
{
// Stubs for  messages
void LogMessage(const char*,...) { }

// Stubs for search_tool.cc
SearchTool::SearchTool(char const*, bool) { }
SearchTool::~SearchTool() = default;
void SearchTool::add(const char*, unsigned, int, bool) { }
void SearchTool::add(const char*, unsigned, void*, bool) { }
void SearchTool::add(const uint8_t*, unsigned, int, bool) { }
void SearchTool::add(const uint8_t*, unsigned, void*, bool) { }
void SearchTool::prep() { }
void SearchTool::reload() { }
}

