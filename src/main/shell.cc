//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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
#include <cstring>
#include <stdexcept>

#include "log/messages.h"
#include "lua/lua.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// helper functions
//-------------------------------------------------------------------------

// FIXIT-M Shell::panic() works on Linux but on OSX we can't throw from lua
// to C++.  unprotected lua calls could be wrapped in a pcall to ensure lua
// panics don't kill the process.  or we can not use lua for the shell.  :(

string Shell::fatal;

[[noreturn]] int Shell::panic(lua_State* L)
{
    fatal = lua_tostring(L, -1);
    throw runtime_error(fatal);
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

static void run_config(lua_State* L, const char* t)
{
    Lua::ManageStack ms(L);

    lua_getglobal(L, "snort_config");
    lua_getglobal(L, t);

    assert(lua_isfunction(L, -2));

    if ( lua_pcall(L, 1, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        FatalError("%s\n", err);
    }
}

static bool config_lua(
    lua_State* L, const char* file, string& s, const char* tweaks, bool is_fatal)
{
    if ( file && *file )
        if (!load_config(L, file, tweaks, is_fatal))
            return false;

    if ( !s.empty() )
        load_string(L, s.c_str());

    run_config(L, "_G");

    return true;
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

    lua_atpanic(lua, Shell::panic);
    luaL_openlibs(lua);

    if ( s )
        file = s;

    parse_from = get_parse_file();

    loaded = false;
    load_string(lua, ModuleManager::get_lua_bootstrap());

    if ( load_defaults )
        load_string(lua, ModuleManager::get_lua_coreinit());
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

    if ( !config_lua(lua, path.c_str(), overrides, sc->tweaks.c_str(), is_fatal) )
        return false;

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

