//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// shell.h author Russ Combs <rucombs@cisco.com>

#ifndef SHELL_H
#define SHELL_H

// Shell encapsulates a Lua state.  There is one for each policy file.

#include <list>
#include <set>
#include <stack>
#include <string>

#include "dump_config/config_data.h"
#include "framework/parameter.h"
#include "policy.h"

struct lua_State;

class BaseConfigNode;
class ConfigOutput;

namespace snort
{
struct SnortConfig;
class Value;
}

class Shell
{
public:
    typedef std::set<std::string> Allowlist;

    Shell(const char* file = nullptr, bool load_defaults = false);
    ~Shell();

    void set_file(const char*);
    void set_overrides(const char*);
    void set_overrides(Shell*);

    bool configure(snort::SnortConfig*, bool is_root = false);
    void install(const char*, const struct luaL_Reg*);
    void execute(const char*, std::string&);

    const char* get_file() const
    { return file.c_str(); }

    const char* get_from() const
    { return parse_from.c_str(); }

    bool get_loaded() const
    { return loaded; }

    lua_State* get_lua() const
    { return lua; }

    void set_user_network_policy();

public:
    static bool is_trusted(const std::string& key);
    static void allowlist_append(const char* keyword, bool is_prefix);

    static void config_open_table(bool is_root_node, bool is_list, int idx,
        const std::string& table_name, const snort::Parameter* p);
    static void set_config_value(const std::string& fqn, const snort::Value& value);
    static void add_config_child_node(const std::string& node_name, snort::Parameter::Type type,
        bool is_root_list_item);
    static void update_current_config_node(const std::string& node_name = "");
    static void config_close_table();
    static void set_config_output(ConfigOutput* config_output);
    static void clear_config_output();

    static void set_lua_sandbox(const char* s)
    { lua_sandbox = s; }

    static void set_network_policy_user_id(lua_State*, uint32_t user_id);

private:
    static void add_config_root_node(const std::string& root_name, snort::Parameter::Type type);

private:
    [[noreturn]] static int panic(lua_State*);
    static Shell* get_current_shell();

private:
    static std::string fatal;
    static std::stack<Shell*> current_shells;
    static ConfigOutput* s_config_output;
    static BaseConfigNode* s_current_node;
    static bool s_close_table;
    static std::string lua_sandbox;
    static const char* const lua_shell_id;

private:
    void clear_allowlist()
    {
        allowlist.clear();
        internal_allowlist.clear();
        allowlist_prefixes.clear();
    }

    const Allowlist& get_allowlist() const
    { return allowlist; }

    const Allowlist& get_internal_allowlist() const
    { return internal_allowlist; }

    const Allowlist& get_allowlist_prefixes() const
    { return allowlist_prefixes; }

    void print_allowlist() const;
    void allowlist_update(const char* keyword, bool is_prefix);

    bool load_lua_sandbox();
    bool set_sandbox_env();
    bool load_string(const char* s, bool load_in_sandbox, const char* message);
    bool load_config(const char* file, bool load_in_sandbox);

private:
    bool loaded;
    bool bootstrapped = false;
    lua_State* lua;
    std::string file;
    std::string parse_from;
    std::string overrides;
    Allowlist allowlist;
    Allowlist internal_allowlist;
    Allowlist allowlist_prefixes;
    ConfigData config_data;
    uint32_t network_user_policy_id = UNDEFINED_NETWORK_USER_POLICY_ID;
    bool load_defaults;
};

#endif

