/*
**  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
**
*/
// script_manager.cc author Russ Combs <rucombs@cisco.com>

#include "script_manager.h"

#include <string>
#include <vector>
#include <lua.hpp>

#include "ips_manager.h"
#include "framework/ips_option.h"
#include "ips_options/ips_luajit.h"
#include "parser/parser.h"
#include "helpers/directory.h"

// FIXIT this approach results in N * K lua states where
// N ::= number of instances of script + args and
// K ::= number of threads
// change to create K lua states here for each script + args
// and change LuaJITOption() to get reference to thread states
// ultimately should look into changing detection engine to 
// keep just one copy of rule option + args

using namespace std;
static const char* script_ext = ".lua";

class LuaIpsApi
{
public:
    LuaIpsApi(string& name, unsigned ver, string& chunk);

public:
    string name;
    string chunk;
    IpsApi api;
};

static vector<BaseApi*> ips_api;
static vector<LuaIpsApi*> ips_options;

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static LuaIpsApi* find_api(const char* key)
{
    for ( auto p : ips_options )
        if ( p->name == key )
            return p;

    return nullptr;
}

static IpsOption* ctor(SnortConfig*, char* args, struct OptTreeNode*)
{
    const char* key = IpsManager::get_option_keyword();
    LuaIpsApi* api = find_api(key);

    if ( !api )
        return nullptr;

    return new LuaJITOption(api->name.c_str(), api->chunk, args);
}

static void dtor(IpsOption* p)
{
    delete p;
}

LuaIpsApi::LuaIpsApi(string& s, unsigned ver, string& c)
{
    name = s;
    chunk = c;

    api.base.type = PT_IPS_OPTION;
    api.base.name = name.c_str();
    api.base.version = ver;
    api.base.api_version = IPSAPI_VERSION;

    api.ginit = api.gterm = nullptr;
    api.tinit = api.tterm = nullptr;

    api.ctor = ctor;
    api.dtor = dtor;
    api.verify = nullptr;
}

//-------------------------------------------------------------------------
// lua foo
//-------------------------------------------------------------------------

static bool get_field (lua_State* L, const char* key, int& value)
{
    lua_pushstring(L, key);
    lua_gettable(L, -2);

    if ( !lua_isnumber(L, -1) )
    {
        ParseWarning("%s is not a number", key);
        lua_pop(L, 1);
        return false;
    }

    value = (long)lua_tonumber(L, -1);
    lua_pop(L, 1);

    return true;
}

static bool get_field (lua_State* L, const char* key, string& value)
{
    lua_pushstring(L, key);
    lua_gettable(L, -2);

    if ( !lua_isstring(L, -1) )
    {
        ParseWarning("%s is not a string", key);
        lua_pop(L, 1);
        return false;
    }

    value = lua_tostring(L, -1);
    lua_pop(L, 1);

    return true;
}

static int dump(lua_State*, const void* p, size_t sz, void* ud)
{
    string* s = (string*)ud;
    s->append((char*)p, sz);
    return 0;
}

static void load_script(const char* f)
{
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);

    if ( luaL_loadfile(L, f) )
    {
        ParseWarning("can't load %s: %s", f, lua_tostring(L, -1));
        return;
    }

    // lua_pcall() pops the function so we push it again first
    // if this is a copy, there must be a cheaper alternative
    lua_pushvalue(L, -1);

    if ( lua_pcall(L, 0, 0, 0) )
    {
        ParseWarning("can't init %s: %s", f, lua_tostring(L, -1));
        return;
    }

    lua_getglobal(L, "plugin");

    if ( !lua_istable(L, -1) )
    {
        ParseWarning("can't get plugin from %s", f);
        return;
    }

    int ver = -1;
    string type, name, chunk;

    if ( !get_field(L, "type", type) || type != "ips_option" )
    {
        ParseError("unknown plugin type in %s = '%s'", f, type.c_str());
        return;
    }

    if ( !get_field(L, "name", name) )
    {
        ParseError("%s::%s needs name", f, type.c_str());
        return;
    }

    if ( !get_field(L, "version", ver) )
        ver = 0;

    lua_pop(L, 1);

    if ( lua_dump(L, dump, &chunk) )
    {
        ParseError("%s::%s can't save chunk", f, name.c_str());
        return;
    }

    LuaIpsApi* lapi = new LuaIpsApi(name, ver, chunk);
    ips_options.push_back(lapi);
    lua_close(L);
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void ScriptManager::load_scripts(const char* s)
{
    if ( !s )
        return;

    vector<char> buf(s, s+strlen(s)+1);
    char* last;
    
    s = strtok_r(&buf[0], ":", &last);

    while ( s )
    {
        Directory d(s);
        const char* f;

        while ( (f = d.next(script_ext)) )
            load_script(f);

        s = strtok_r(nullptr, ":", &last);
    }
}

const BaseApi** ScriptManager::get_ips_options()
{
    ips_api.clear();

    for ( auto p : ips_options )
        ips_api.push_back(&p->api.base);

    ips_api.push_back(nullptr);

    return (const BaseApi**)&ips_api[0];
}

void ScriptManager::release_scripts()
{
    for ( auto p : ips_options )
        if ( p )
            delete p;

    ips_options.clear();
    ips_api.clear();
}

