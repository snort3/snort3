/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// shell.cc author Russ Combs <rucombs@cisco.com>

#include "shell.h"

#include <assert.h>
#include <string.h>
#include <string>
#include <lua.hpp>

#include "framework/module.h"
#include "managers/module_manager.h"
#include "parser/parser.h"

using namespace std;

static lua_State* s_lua = nullptr;
static string s_overrides;

static const char* required = "require('snort_config'); ";

//-------------------------------------------------------------------------
// helper functions
//-------------------------------------------------------------------------

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

static void load_config(lua_State* L, const char* file)
{
    if ( luaL_loadfile(L, file) )
    {
        FatalError("can't load %s: %s\n", file, lua_tostring(L, -1));
        return;
    }

    if ( lua_pcall(L, 0, 0, 0) )
    {
        FatalError("can't init %s: %s\n", file, lua_tostring(L, -1));
        return;
    }
}

static void load_overrides(lua_State* L)
{
    if ( luaL_loadstring(L, s_overrides.c_str()) )
    {
        FatalError("can't load overrides: %s\n", lua_tostring(L, -1));
        return;
    }

    if ( lua_pcall(L, 0, 0, 0) )
    {
        FatalError("can't init overrides: %s\n", lua_tostring(L, -1));
        return;
    }
}

static void run_config(lua_State* L)
{
    lua_getglobal(L, "snort_config");

    if ( !lua_isfunction(L, -1) )
        FatalError("%s\n", "snort_config is required");

    else if ( lua_pcall(L, 0, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        FatalError("%s\n", err);
    }
}

static void config_lua(
    lua_State* L, SnortConfig* sc, const char* file)
{
    ModuleManager::set_config(sc);

    if ( file && *file )
        load_config(L, file);

    if ( s_overrides.size() )
        load_overrides(L);

    run_config(L);

    if ( ModuleManager::get_errors() )
        FatalError("%s\n", "see prior configuration errors");

    ModuleManager::set_config(nullptr);
}

//-------------------------------------------------------------------------
// public metods
//-------------------------------------------------------------------------

void Shell::init()
{
    s_lua = luaL_newstate();
    luaL_openlibs(s_lua);
}

void Shell::term()
{
    if ( s_lua )
        lua_close(s_lua);
}

void Shell::configure(SnortConfig* sc, const char* file)
{
    assert(s_lua);
    config_lua(s_lua, sc, file);
}

void Shell::install(const char* name, const luaL_reg* reg)
{
    if ( s_lua )
        luaL_register(s_lua, name, reg);
}

void Shell::execute(const char* s)
{
    int err = luaL_loadbuffer(s_lua, s, strlen(s), "shell");
    
    if ( !err )
        err = lua_pcall(s_lua, 0, 0, 0);

    if (err)
    {
        fprintf(stderr, "%s", lua_tostring(s_lua, -1));
        lua_pop(s_lua, 1);
    }
}

void Shell::set_overrides(const char* s)
{
    if ( s_overrides.empty() )
        s_overrides += required;

    s_overrides += s;
}

