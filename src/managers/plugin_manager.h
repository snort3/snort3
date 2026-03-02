//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "framework/base_api.h"
#include "managers/plugin.h"

namespace snort
{
class Module;
struct SnortConfig;
}

class PlugContext;
class PlugInterface;
struct PlugSet;

class PluginManager
{
public:
    // construct the working set of plugins
    static void init();

    static void load_plugins(const std::string& lib_paths);
    static void load_plugins(const snort::BaseApi**);
    static void load_plugin(const snort::BaseApi*, class LuaApi*, const char* src);

    static void reload_plugins(const char*, bool allow_mising_so_rules);
    static void unload_plugins();

    static void capture_plugins(snort::SnortConfig*);
    static void revert_plugins(snort::SnortConfig*);

    static void thread_init();
    static void thread_reinit(const snort::SnortConfig*);
    static void thread_term(bool trace);

    static void set_plugins(PlugSet*);
    static void clear_plugins();
    static void set_close_all_plugins(bool);

    static const char* get_current_plugin();
    static const char* get_available_plugins(PlugType, const char* prefix = nullptr);

    static void add_module(snort::Module*);
    static snort::Module* get_module(const char*);
    static snort::Module* get_module(const char*, const snort::BaseApi*&);
    static std::list<snort::Module*> get_all_modules(const snort::SnortConfig* = nullptr);

    // use the working set of plugins
    static void list_plugins(const char* type = nullptr);
    static void show_plugins(const char* type);
    static void dump_plugins();

    static void release_plugins();
    static void release_plugins(struct PlugSet*);

    static PluginPtr get_plugin(const char* name);

    static PlugType get_type(const char*);
    static const char* get_type_name(PlugType);

    static const snort::BaseApi* get_api(const char* name);
    static PlugContext* get_context(const char* name);

    static PlugInterface* get_interface(const char* name);
    static std::vector<PlugInterface*> get_interfaces(PlugType);

    static void instantiate(snort::Module*, snort::SnortConfig*, const char* name);
    static void set_instantiated(const char* name);

    typedef void (*BaseFunc)(const snort::BaseApi*, void* user);
    static unsigned for_each(PlugType, BaseFunc, void* user = nullptr);  // returns loop count

    typedef void (*PlugFunc)(PlugInterface*, void* user);
    static unsigned for_each(PlugType, PlugFunc, void* user = nullptr);  // returns loop count

    static void empty_trash();
};

#endif

