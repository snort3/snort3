//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// script_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef SCRIPT_MANAGER_H
#define SCRIPT_MANAGER_H

// Factory for Lua script plugins used for IpsOptions and Loggers implemented
// in Lua.  Runtime use is via the actual plugin type manager.

#include <string>
#include <vector>

#include "framework/base_api.h"

//-------------------------------------------------------------------------

class ScriptManager
{
public:
    static void load_scripts(const std::vector<std::string>& paths);
    static void release_scripts();
    static const snort::BaseApi** get_plugins();
    static std::string* get_chunk(const char* key);
};

#endif

