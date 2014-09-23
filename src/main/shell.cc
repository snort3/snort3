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

static void load_overrides(lua_State* L, string& s)
{
    if ( luaL_loadstring(L, s.c_str()) )
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
    lua_State* L, const char* file, string& s)
{

    if ( file && *file )
        load_config(L, file);

    if ( s.size() )
        load_overrides(L, s);

    run_config(L);

    if ( int k = ModuleManager::get_errors() )
        FatalError("see prior %d errors\n", k);
}

//-------------------------------------------------------------------------
// public metods
//-------------------------------------------------------------------------

Shell::Shell(const char* s)
{
    lua = luaL_newstate();
    luaL_openlibs(lua);

    if ( s )
        file = s;

    loaded = false;
}

Shell::~Shell()
{
    lua_close(lua);
}

void Shell::set_file(const char* s)
{
    assert(!file.size());
    file = s;
}

void Shell::set_overrides(const char* s)
{
    if ( overrides.empty() )
        overrides = required;

    overrides += s;
}

void Shell::configure(SnortConfig* sc)
{
    assert(file.size()); // FIXIT-M -- provide detailed error message. Will be confusing for an end user
    ModuleManager::set_config(sc);
    config_lua(lua, file.c_str(), overrides);
    ModuleManager::set_config(nullptr);
    loaded = true;
}

void Shell::install(const char* name, const luaL_reg* reg)
{
    if ( !strcmp(name, "snort") )
        luaL_register(lua, "_G", reg);

    luaL_register(lua, name, reg);
}

void Shell::execute(const char* cmd, string& rsp)
{
    int err = luaL_loadbuffer(lua, cmd, strlen(cmd), "shell");
    
    if ( !err )
        err = lua_pcall(lua, 0, 0, 0);

    if (err)
    {
        rsp = lua_tostring(lua, -1);
        lua_pop(lua, 1);
    }
}

