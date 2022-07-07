//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// module_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef MODULE_MANAGER_H
#define MODULE_MANAGER_H

// Factory for Modules, including all builtin and plugin modules.
// Modules are strictly used during parse time.

#include <cstdint>
#include <list>
#include <mutex>
#include <set>

#include "main/analyzer_command.h"
#include "main/snort_types.h"

//-------------------------------------------------------------------------

class Shell;

namespace snort
{
struct BaseApi;
class Module;
struct SnortConfig;

class ModuleManager
{
public:
    static void init();
    static void term();

    static void add_module(Module*, const BaseApi* = nullptr);
    SO_PUBLIC static Module* get_module(const char*);
    static Module* get_default_module(const char*, SnortConfig*);
    SO_PUBLIC static std::list<Module*> get_all_modules();

    static const char* get_lua_coreinit();
    static const char* get_includer(const char* module);

    static void list_modules(const char* = nullptr);
    static void dump_modules();
    static void show_modules();
    static void show_modules_json();
    static void show_module(const char*);

    static bool gid_in_use(uint32_t);

    // output for matching module name; prefix is sufficient if not exact
    static void show_configs(const char* = nullptr, bool exact = false);
    static void show_commands(const char* = nullptr, bool exact = false);
    static void show_gids(const char* = nullptr, bool exact = false);
    static void show_pegs(const char* = nullptr, bool exact = false);
    static void show_rules(const char* = nullptr, bool exact = false);

    static void dump_rules(const char* = nullptr, const char* opts = nullptr);
    static void dump_defaults(const char* = nullptr);

    static void load_params();
    static const struct Parameter* get_parameter(const char* table, const char* option);

    static void load_commands(Shell*);
    static void load_rules(SnortConfig*);
    static void set_config(SnortConfig*);
    static void reload_module(const char*, SnortConfig*);

    static void reset_errors();
    static unsigned get_errors();

    static void dump_stats(const char* skip = nullptr, bool dynamic = false);

    static void accumulate(const char* except = nullptr);
    static void accumulate_module(const char* name);
    static void reset_stats(SnortConfig*);
    static void reset_stats(clear_counter_type_t);

    static void clear_global_active_counters();

    static std::set<uint32_t> gids;
    SO_PUBLIC static std::mutex stats_mutex;
};
}

#endif

