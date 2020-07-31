//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
#include <stdexcept>

#include "config_tree.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"
#include "utils/stats.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// helper functions
//-------------------------------------------------------------------------

string Shell::fatal;
std::stack<Shell*> Shell::current_shells;

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

bool Shell::is_whitelisted(const std::string& key)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return false;

    const Whitelist& whitelist = sh->get_whitelist();
    const Whitelist& internal_whitelist = sh->get_internal_whitelist();
    const Whitelist& whitelist_prefixes = sh->get_whitelist_prefixes();

    for ( const auto& prefix : whitelist_prefixes )
    {
        if (key.compare(0, prefix.length(), prefix) == 0)
            return true;
    }

    if ( whitelist.find(key) != whitelist.end() )
        return true;

    if ( internal_whitelist.find(key) != internal_whitelist.end() )
        return true;

    return false;
}

void Shell::whitelist_append(const char* keyword, bool is_prefix)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    sh->whitelist_update(keyword, is_prefix);
}

void Shell::config_open_table(bool is_root_node, bool is_list, int idx,
    const std::string& table_name, const Parameter* p)
{
    Parameter::Type node_type = is_list ? Parameter::PT_LIST : Parameter::PT_TABLE;
    if ( is_root_node )
        add_config_root_node(table_name, node_type);
    else
    {
        if ( p )
            node_type = p->type;

        if ( node_type == Parameter::PT_TABLE )
            update_current_config_node(table_name);
        else
        {
            if ( idx )
                node_type = Parameter::PT_TABLE;

            add_config_child_node(table_name, node_type);
        }
    }
}

void Shell::add_config_child_node(const std::string& node_name, snort::Parameter::Type type)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    std::string name;
    if ( sh->s_current_node->get_name() != node_name )
        name = node_name;

    auto new_node = new TreeConfigNode(sh->s_current_node, name, type);
    sh->s_current_node->add_child_node(new_node);
    sh->s_current_node = new_node;
}

void Shell::add_config_root_node(const std::string& root_name, snort::Parameter::Type node_type)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    sh->s_current_node = new TreeConfigNode(nullptr, root_name, node_type);
    sh->config_trees.push_back(sh->s_current_node);
}

void Shell::update_current_config_node(const std::string& node_name)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    if ( !sh->s_current_node )
        return;

    // node has been added during setting default options
    if ( !node_name.empty() )
        sh->s_current_node = sh->s_current_node->get_node(node_name);
    else if ( sh->s_current_node->get_parent_node() and
        sh->s_current_node->get_type() == Parameter::PT_TABLE and
        !sh->s_current_node->get_name().empty() )
            sh->s_current_node = sh->s_current_node->get_parent_node();

    assert(sh->s_current_node);
}

void Shell::config_close_table()
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    if ( !sh->s_current_node )
        return;

    sh->s_current_node = sh->s_current_node->get_parent_node();
}

void Shell::set_config_value(const snort::Value& value)
{
    Shell* sh = Shell::get_current_shell();

    if ( !sh )
        return;

    if ( !sh->s_current_node )
        return;

    // lua interpreter does not call open_table for simple list items like (string)
    // we have to add tree node for this item too
    if ( sh->s_current_node->get_type() == Parameter::PT_LIST )
    {
        add_config_child_node("", Parameter::PT_TABLE);
        sh->s_current_node->add_child_node(new ValueConfigNode(sh->s_current_node, value));
        sh->s_current_node = sh->s_current_node->get_parent_node();

        return;
    }
    
    BaseConfigNode* child_node = nullptr;
    for ( auto node : sh->s_current_node->get_children() )
    {
        child_node = node->get_node(value.get_name());
        if ( child_node )
            break;
    }

    if ( !child_node )
        sh->s_current_node->add_child_node(new ValueConfigNode(sh->s_current_node, value));
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

static bool load_config(lua_State* L, const char* file, const char* tweaks, bool is_fatal)
{
    Lua::ManageStack ms(L);
    if ( luaL_loadfile(L, file) )
    {
        if (is_fatal)
            FatalError("can't load %s: %s\n", file, lua_tostring(L, -1));
        else
            ParseError("can't load %s: %s\n", file, lua_tostring(L, -1));
        return false;
    }
    if ( tweaks and *tweaks )
    {
        lua_pushstring(L, tweaks);
        lua_setglobal(L, "tweaks");
    }

    if ( lua_pcall(L, 0, 0, 0) )
        FatalError("can't init %s: %s\n", file, lua_tostring(L, -1));

    return true;
}

static void load_string(lua_State* L, const char* s)
{
    Lua::ManageStack ms(L);

    if ( luaL_loadstring(L, s) )
    {
        const char* err = lua_tostring(L, -1);
        if ( strstr(err, "near '#'") )
            ParseError("this doesn't look like Lua.  Comments start with --, not #.");
        FatalError("can't load overrides: %s\n", err);
    }

    if ( lua_pcall(L, 0, 0, 0) )
        FatalError("can't init overrides: %s\n", lua_tostring(L, -1));
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

Shell::Shell(const char* s, bool load_defaults)
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
    load_string(lua, ModuleManager::get_lua_bootstrap());
    bootstrapped = true;

    if ( load_defaults )
        load_string(lua, ModuleManager::get_lua_coreinit());

    current_shells.pop();
}

Shell::~Shell()
{
    lua_close(lua);
}

void Shell::set_file(const char* s)
{
    file = s;
}

void Shell::set_overrides(const char* s)
{
    overrides += s;
}

void Shell::set_overrides(Shell* sh)
{
    overrides += sh->overrides;
}

bool Shell::configure(SnortConfig* sc, bool is_fatal, bool is_root)
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
        if ( is_fatal )
            FatalError("can't find %s\n", file.c_str());
        else
            ParseError("can't find %s\n", file.c_str());
        return false;
    }

    push_parse_location(code, path.c_str(), file.c_str(), 0);

    current_shells.push(this);

    if (!path.empty() and !load_config(lua, path.c_str(), sc->tweaks.c_str(), is_fatal))
    {
        current_shells.pop();
        return false;
    }

    if ( !overrides.empty() )
        load_string(lua, overrides.c_str());

    if ( SnortConfig::get_conf()->log_verbose() )
        print_whitelist();

    load_string(lua, ModuleManager::get_lua_finalize());

    clear_whitelist();

    if ( SnortConfig::get_conf()->dump_config() )
    {
        sort_config();
        print_config_text();
        clear_config_tree();
    }

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

static void print_list(const Shell::Whitelist& wlist, const std::string& msg)
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
void Shell::sort_config()
{
    config_trees.sort([](const BaseConfigNode* l, const BaseConfigNode* r)
        { return l->get_name() < r->get_name(); });
}

void Shell::print_config_text() const
{
    std::string output("consolidated config for ");
    output += file;
    LogConfig("%s\n", output.c_str());

    for ( const auto config_tree: config_trees )
        ConfigTextFormat::print(config_tree, config_tree->get_name());
}

void Shell::clear_config_tree()
{
    for ( auto config_tree: config_trees )
        BaseConfigNode::clear_nodes(config_tree);

    config_trees.clear();
}

void Shell::print_whitelist() const
{
    std::string output;
    if ( !whitelist.empty() )
    {
        output = "Lua Whitelist Keywords for " + file + ":";
        print_list(whitelist, output);
    }

    if ( !whitelist_prefixes.empty() )
    {
        output = "Lua Whitelist Prefixes for " + file + ":";
        print_list(whitelist_prefixes, output);
    }
}

void Shell::whitelist_update(const char* s, bool is_prefix)
{
    Whitelist* wlist = nullptr;
    if ( is_prefix )
        wlist = &whitelist_prefixes;
    else if ( !bootstrapped )
        wlist = &internal_whitelist;
    else
        wlist = &whitelist;

    if ( s )
        wlist->emplace(s);
}

