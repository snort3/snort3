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
// module_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef MODULE_MANAGER_H
#define MODULE_MANAGER_H

// Factory for Modules, including all builtin and plugin modules.
// Modules are strictly used during parse time.

#include <cstdint>
#include <set>
#include <list>

//-------------------------------------------------------------------------

namespace snort
{
struct BaseApi;
class Module;
struct SnortConfig;
}

class Shell;

class ModuleManager
{
public:
    static void init();
    static void term();

    static void add_module(snort::Module*, const snort::BaseApi* = nullptr);
    static snort::Module* get_module(const char*);
    static snort::Module* get_default_module(const char*, snort::SnortConfig*);
    static const char* get_current_module();
    static std::list<snort::Module*> get_all_modules();

    static void list_modules(const char* = nullptr);
    static void dump_modules();
    static void show_modules();
    static void show_module(const char*);

    static bool gid_in_use(uint32_t);

    // output for matching module name; prefix is sufficient if not exact
    static void show_configs(const char* = nullptr, bool exact = false);
    static void show_commands(const char* = nullptr, bool exact = false);
    static void show_gids(const char* = nullptr, bool exact = false);
    static void show_pegs(const char* = nullptr, bool exact = false);
    static void show_rules(const char* = nullptr, bool exact = false);

    static void dump_msg_map(const char* = nullptr);
    static void dump_rules(const char* = nullptr);
    static void dump_defaults(const char* = nullptr);

    static void load_commands(Shell*);
    static void load_rules(snort::SnortConfig*);
    static void set_config(snort::SnortConfig*);
    static void reload_module(const char*, snort::SnortConfig*);

    static void reset_errors();
    static unsigned get_errors();

    static void dump_stats(snort::SnortConfig*, const char* skip = nullptr, bool dynamic = false);
 
    static void accumulate(snort::SnortConfig*);
    static void reset_stats(snort::SnortConfig*);

    static std::set<uint32_t> gids;
};

extern "C"
{
    // returns the correct path component to use for referencing the file 
    const char* push_relative_path(const char*);
    void pop_relative_path();
}

#endif

