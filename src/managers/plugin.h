//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// plugin.h author Russ Combs <rucombs@cisco.com>

#ifndef PLUGIN_H
#define PLUGIN_H

// encapsulates lib, API, and module

#include <memory>
#include <string>

#include "framework/base_api.h"

namespace snort
{
class Module;
}

struct Plugin
{
    std::string source;
    const char* type;

    void* handle = nullptr;
    const snort::BaseApi* api = nullptr;
    snort::Module* mod = nullptr;
    class LuaApi* luapi = nullptr;
    class PlugInterface* pin = nullptr;

    ~Plugin();
    void setup(const char* type, const char* src, void*, const snort::BaseApi*);

    const char* get_name();
    const char* get_help();
};

using PluginPtr = std::shared_ptr<Plugin>;

#endif

