//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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

// ua_fp_stubs.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "search_engines/search_tool.h"

namespace snort
{
void SearchTool::add(const char*, unsigned, int, bool, bool) { }
void SearchTool::add(const uint8_t*, unsigned, int, bool, bool) { }
void SearchTool::add(const uint8_t*, unsigned, void*, bool, bool) { }

void SearchTool::reload() { }

int SearchTool::find(const char*, unsigned, MpseMatch, int&, bool, void*)
{ return 0; }

int SearchTool::find(const char*, unsigned, MpseMatch, bool, void*)
{ return 0; }

int SearchTool::find_all(const char*, unsigned, MpseMatch, bool, void*, const SnortConfig*)
{ return 0; }
}

