//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
// shell.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "shell.h"

#include <unistd.h>

#include <cassert>
#include <fstream>
#include <stdexcept>

#include "dump_config/config_output.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"
#include "utils/stats.h"

#include "lua_bootstrap.h"
#include "lua_finalize.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// helper functions
//-------------------------------------------------------------------------

static const char* versions[] = {
    "SNORT_VERSION",
    "SNORT_MAJOR_VERSION",
    "SNORT_MINOR_VERSION",
    "SNORT_PATCH_VERSION",
    "SNORT_SUBLEVEL_VERSION",
    nullptr
};

static void install_version_strings(lua_State* L)
{
    assert(versions[0]);

#ifdef BUILD
    lua_pushstring(L, VERSION "-" BUILD);
#else
    lua_pushstring(L, VERSION);
#endif
    lua_setglobal(L, versions[0]);

    std::istringstream vs(VERSION);
    for ( int i = 1 ; versions[i] ; i++ )
    {
        std::string tmp;
        int num = 0;
        std::getline(vs, tmp, '.');

        if ( !tmp.empty() )
            num = stoi(tmp);

        lua_pushinteger(L, num);
        lua_setglobal(L, versions[i]);
    }
}

string Shell::fatal;
std::stack<Shell*> Shell::current_shells;
ConfigOutput* Shell::s_config_output = nullptr;
BaseConfigNode* Shell::s_current_node = nullptr;
bool Shell::s_close_table = true;
string Shell::lua_sandbox;

// FIXIT-M Shell::panic() works on Linux but on OSX we can't throw from lua
// to C++.  unprotected lua calls could be wrapped in a pcall to ensure lua
// panics don't kill the process.  or we can not use lua for the shell.  :(
[[noreturn]] int Shell::panic(lua_State* L)
{
    fatal = lua_tostring(L, -1);
    throw runtime_error(fatal);
}

Shell* Shell::get_current_shell()
{
    if ( !current_shells.empty() )
        return current_shells.top();

    return nullptr;
}

void Shell::set_config_output(ConfigOutput* output)
{ s_config_output = output; }

void Shell::clear_config_output()
{
    s_config_output = nullptr;
    s_current_node = nullptr;
}

bool Shell::is_trusted(const std::string& key)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return false;

    const Allowlist& allowlist = sh->get_allowlist();
    const Allowlist& internal_allowlist = sh->get_internal_allowlist();
    const Allowlist& allowlist_prefixes = sh->get_allowlist_prefixes();

    for ( const auto& prefix : allowlist_prefixes )
    {
        if (key.compare(0, prefix.length(), prefix) == 0)
            return true;
    }

    if ( allowlist.find(key) != allowlist.end() )
        return true;

    if ( internal_allowlist.find(key) != internal_allowlist.end() )
        return true;

    return false;
}

void Shell::allowlist_append(const char* keyword, bool is_prefix)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    sh->allowlist_update(keyword, is_prefix);
}

void Shell::config_open_table(bool is_root_node, bool is_list, int idx,
    const std::string& table_name, const Parameter* p)
{
    if ( !s_config_output )
        return;

    Parameter::Type node_type = is_list ? Parameter::PT_LIST : Parameter::PT_TABLE;
    if ( is_root_node )
        add_config_root_node(table_name, node_type);
    else
    {
        if ( p )
            node_type = p->type;

        if ( node_type == Parameter::PT_MULTI )
        {
            s_close_table = false;
            return;
        }

        if ( node_type == Parameter::PT_TABLE )
            update_current_config_node(table_name);
        else
        {
            if ( idx )
                node_type = Parameter::PT_TABLE;

            add_config_child_node(table_name, node_type, idx);
        }
    }
}

void Shell::add_config_child_node(const std::string& node_name, snort::Parameter::Type type,
    bool is_root_list_item)
{
    if ( !s_config_output || !s_current_node )
        return;

    // element of the top-level list is anonymous
    std::string name = ( !is_root_list_item && s_current_node->get_name() != node_name ) ?
        node_name : "";

    auto new_node = new TreeConfigNode(s_current_node, name, type);
    s_current_node->add_child_node(new_node);
    s_current_node = new_node;
}

void Shell::add_config_root_node(const std::string& root_name, snort::Parameter::Type node_type)
{
    if ( !s_config_output )
        return;

    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    sh->s_current_node = new TreeConfigNode(nullptr, root_name, node_type);
    sh->config_data.add_config_tree(sh->s_current_node);
}

void Shell::update_current_config_node(const std::string& node_name)
{
    if ( !s_config_output || !s_current_node )
        return;

    // node has been added during setting default options
    if ( !node_name.empty() )
        s_current_node = s_current_node->get_node(node_name);
    else if ( s_current_node->get_parent_node() and
        s_current_node->get_type() == Parameter::PT_TABLE and
        !s_current_node->get_name().empty() )
            s_current_node = s_current_node->get_parent_node();

    assert(s_current_node);
}

void Shell::config_close_table()
{
    if ( !s_config_output )
        return;

    if ( !s_close_table )
    {
        s_close_table = true;
        return;
    }

    if ( !s_current_node )
        return;

    s_current_node = s_current_node->get_parent_node();
}

void Shell::set_config_value(const std::string& fqn, const snort::Value& value)
{
    if ( !s_config_output || !s_current_node )
        return;

    // don't give names to list elements
    if ( s_current_node->get_type() == Parameter::PT_LIST )
    {
        s_current_node->add_child_node(new ValueConfigNode(s_current_node, value, ""));
        return;
    }

    BaseConfigNode* child_node = nullptr;

    std::string custom_name;
    if ( strchr(value.get_name(), '$') )
        custom_name = fqn.substr(fqn.find_last_of(".") + 1);

    for ( auto node : s_current_node->get_children() )
    {
        if ( (node->get_type() == Parameter::PT_MULTI) and (node->get_name() == value.get_name()) )
        {
            child_node = node;
            break;
        }

        if ( !custom_name.empty() )
            child_node = node->get_node(custom_name);
        else
            child_node = node->get_node(value.get_name());

        if ( child_node )
            break;
    }

    if ( !child_node )
        s_current_node->add_child_node(new ValueConfigNode(s_current_node, value, custom_name));
    else
        child_node->set_value(value);
}

// FIXIT-L shell --pause should stop before loading config so Lua state
// can be examined and modified.

#if 0
// :( it does not look possible to get file and line after load
static int get_line_number(lua_State* L)
{
    lua_Debug ar;
    lua_getstack(L, 1, &ar);
    lua_getinfo(L, "nSl", &ar);
    return ar.currentline;
}

#endif

bool Shell::set_sandbox_env()
{
    lua_getglobal(lua, "sandbox_env");

    if ( lua_istable(lua, -1) )
    {
        if ( !lua_setfenv(lua, -2) )
        {
            ParseError("can't set sandbox environment\n");
            return false;
        }
    }
    else
    {
        ParseError("sandbox environment not defined\n");
        return false;
    }
    return true;
}

bool Shell::load_lua_sandbox()
{
    Lua::ManageStack ms(lua);

    LogMessage("Loading lua sandbox %s:\n", lua_sandbox.c_str());
    if ( luaL_loadfile(lua, lua_sandbox.c_str()) )
    {
        ParseError("can't load lua sandbox %s: %s\n", lua_sandbox.c_str(), lua_tostring(lua, -1));
        return false;
    }

    if ( lua_pcall(lua, 0, 0, 0) )
    {
        ParseError("can't init lua sandbox %s: %s\n", lua_sandbox.c_str(), lua_tostring(lua, -1));
        return false;
    }
    LogMessage("Finished %s:\n", lua_sandbox.c_str());

    lua_getglobal(lua, "sandbox_env");
    if ( !lua_istable(lua, -1) )
    {
        ParseError("sandbox_env table doesn't exist in %s: %s\n", lua_sandbox.c_str(),
            lua_tostring(lua, -1));
        return false;
    }

    lua_getglobal(lua, "create_sandbox_env");
    if ( lua_pcall(lua, 0, 0, 0) != 0 )
    {
        ParseError("can't create sandbox environment %s: %s\n", lua_sandbox.c_str(),
            lua_tostring(lua, -1));
        return false;
    }

    return true;
}

bool Shell::load_string(const char* s, bool load_in_sandbox, const char* message)
{
    Lua::ManageStack ms(lua);

    if ( luaL_loadstring(lua, s) )
    {
        ParseError("can't load %s: %s\n", message, lua_tostring(lua, -1));
        return false;
    }

    if ( load_in_sandbox && !set_sandbox_env() )
        return false;


    if ( lua_pcall(lua, 0, 0, 0) )
    {
        ParseError("can't init %s: %s\n", message, lua_tostring(lua, -1));
        return false;
    }

    return true;
}

bool Shell::load_config(const char* file, bool load_in_sandbox)
{
    if ( load_in_sandbox )
    {
        ifstream in_file(file, ifstream::in);
        if (in_file.get() == 27 )
        {
            ParseError("bytecode is not allowed %s\n", file);
            return false;
        }
    }

    Lua::ManageStack ms(lua);

    if ( luaL_loadfile(lua, file) )
    {
        ParseError("can't load %s: %s\n", file, lua_tostring(lua, -1));
        return false;
    }

    if ( load_in_sandbox && !set_sandbox_env() )
        return false;

    if ( lua_pcall(lua, 0, 0, 0) )
    {
        ParseError("can't init %s: %s\n", file, lua_tostring(lua, -1));
        return false;
    }

    return true;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

Shell::Shell(const char* s, bool load_defaults) :
    config_data(s), load_defaults(load_defaults)
{
    // FIXIT-M should wrap in Lua::State
    lua = luaL_newstate();

    if ( !lua )
        FatalError("Lua state instantiation failed\n");

    current_shells.push(this);

    lua_atpanic(lua, Shell::panic);
    luaL_openlibs(lua);

    if ( s )
        file = s;

    parse_from = get_parse_file();

    loaded = false;
    load_string(lua_bootstrap, false, "bootstrap");
    install_version_strings(lua);
    bootstrapped = true;

    current_shells.pop();
}

Shell::~Shell()
{
    lua_close(lua);
}

void Shell::set_file(const char* s)
{
    file = s;
    config_data.file_name = file;
}

void Shell::set_overrides(const char* s)
{
    overrides += s;
}

void Shell::set_overrides(Shell* sh)
{
    overrides += sh->overrides;
}

bool Shell::configure(SnortConfig* sc, bool is_root)
{
    assert(file.size());
    ModuleManager::set_config(sc);

    //set_*_policy can set to null. this is used
    //to tell which pieces to pick from sub policy
    auto pt = sc->policy_map->get_policies(this);
    if ( pt.get() == nullptr )
        set_default_policy(sc);
    else
    {
        set_inspection_policy(pt->inspection);
        set_ips_policy(pt->ips);
        set_network_policy(pt->network);
    }

    if (!sc->tweaks.empty())
    {
        lua_pushstring(lua, sc->tweaks.c_str());
        lua_setglobal(lua, "tweaks");
    }

    bool load_in_sandbox = true;

    if ( lua_sandbox.empty() )
        load_in_sandbox = false;
    else if ( !load_lua_sandbox() )
        return false;

    if ( load_defaults )
        load_string(ModuleManager::get_lua_coreinit(), load_in_sandbox, "coreinit");

    std::string path = parse_from;
    const char* code;

    if ( !is_root )
        code = get_config_file(file.c_str(), path);
    else
    {
        code = "W";
        path = file;
    }

    if ( !code )
    {
        ParseError("can't find %s\n", file.c_str());
        return false;
    }

    push_parse_location(code, path.c_str(), file.c_str(), 0);

    current_shells.push(this);

    if ( !path.empty() and
        !load_config(path.c_str(), load_in_sandbox) )
    {
        current_shells.pop();
        return false;
    }

    if ( !overrides.empty() )
        load_string(overrides.c_str(), load_in_sandbox, "overrides");

    if ( SnortConfig::log_verbose() )
        print_allowlist();

    load_string(lua_finalize, false, "finalize");

    clear_allowlist();

    auto config_output = Shell::get_current_shell()->s_config_output;
    if ( config_output )
        config_output->dump_config(config_data);

    current_shells.pop();

    set_default_policy(sc);
    ModuleManager::set_config(nullptr);
    loaded = true;

    pop_parse_location();

    return true;
}

void Shell::install(const char* name, const luaL_Reg* reg)
{
    if ( !strcmp(name, "snort") )
        luaL_register(lua, "_G", reg);

    luaL_register(lua, name, reg);
}

void Shell::execute(const char* cmd, string& rsp)
{
    int err = 0;
    Lua::ManageStack ms(lua);

    try
    {
        // FIXIT-L shares logic with chunk
        err = luaL_loadbuffer(lua, cmd, strlen(cmd), "shell");

        if ( !err )
            err = lua_pcall(lua, 0, 0, 0);
    }
    catch (...)
    {
        rsp = fatal;
    }

    if (err)
    {
        rsp = lua_tostring(lua, -1);
        rsp += "\n";
        lua_pop(lua, 1);
    }
}

//-------------------------------------------------------------------------
// Helper methods
//-------------------------------------------------------------------------

static void print_list(const Shell::Allowlist& wlist, const std::string& msg)
{
    LogMessage("\t%s\n", msg.c_str());
    std::string list;

    for ( const auto& wl : wlist )
    {
        list += wl;
        list += ", ";
    }

    if ( !list.empty() )
        list.erase(list.end() - 2, list.end());

    ConfigLogger::log_list(list.c_str());
}

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

void Shell::print_allowlist() const
{
    std::string output;
    if ( !allowlist.empty() )
    {
        output = "Lua Allowlist Keywords for " + file + ":";
        print_list(allowlist, output);
    }

    if ( !allowlist_prefixes.empty() )
    {
        output = "Lua Allowlist Prefixes for " + file + ":";
        print_list(allowlist_prefixes, output);
    }
}

void Shell::allowlist_update(const char* s, bool is_prefix)
{
    Allowlist* wlist = nullptr;
    if ( is_prefix )
        wlist = &allowlist_prefixes;
    else if ( !bootstrapped )
        wlist = &internal_allowlist;
    else
        wlist = &allowlist;

    if ( s )
        wlist->emplace(s);
}

