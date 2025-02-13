//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// plugin_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

//-------------------------------------------------------------------------
// Manages all plugins.  Loading plugins is a 3 step process:
//
// 1. ScriptManager loads available scripts and generates an API
//    for each.
// 2. PluginManager loads all API including static, dynamic, generated.
//    PluginManager retains only the latest version of each.
// 3. API managers, such as IpsManager, use the API to instantiate plugins
//    based on configuration.
//-------------------------------------------------------------------------

#include <map>
#include <memory>
#include <string>

#include "framework/base_api.h"

namespace snort
{
class Module;
struct SnortConfig;
}

class PluginManager
{
public:
    // plugin methods
    static void load_plugins(const snort::BaseApi**);
    static void load_plugins(const std::string& lib_paths);

    static void list_plugins();
    static void show_plugins();
    static void dump_plugins();
    static void release_plugins();

    static PlugType get_type(const char*);
    static const char* get_type_name(PlugType);

    static const snort::BaseApi* get_api(PlugType, const char* name);
    static const char* get_current_plugin();

    static void instantiate(const snort::BaseApi*, snort::Module*, snort::SnortConfig*);
    static void instantiate(const snort::BaseApi*, snort::Module*, snort::SnortConfig*,
        const char* name);

    static const char* get_available_plugins(PlugType);
    static void load_so_plugins(snort::SnortConfig*, bool is_reload = false);
    static void reload_so_plugins(const char*, snort::SnortConfig*);
    static void reload_so_plugins_cleanup(snort::SnortConfig*);
};

struct Plugin;
struct Plugins
{
    std::map<std::string, Plugin> plug_map;
    ~Plugins();
};

struct SoHandle
{
    void* handle;

    SoHandle(void* h) : handle(h) { }
    ~SoHandle();
};

using SoHandlePtr = std::shared_ptr<SoHandle>;

#endif

