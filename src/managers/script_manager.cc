//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// script_manager.cc author Russ Combs <rucombs@cisco.com>

#include "script_manager.h"

#include <string.h>

#include <string>
#include <vector>
#include <luajit-2.0/lua.hpp>

#include "ips_manager.h"
#include "framework/ips_option.h"
#include "framework/logger.h"
#include "managers/plugin_manager.h"
#include "parser/parser.h"
#include "helpers/directory.h"

// FIXIT-P this approach results in N * K lua states where
// N ::= number of instances of script + args and
// K ::= number of threads
// change to create K lua states here for each script + args
// and change LuaJit*() to get reference to thread states
// ultimately should look into changing detection engine to
// keep just one copy of rule option + args

using namespace std;
#define script_ext ".lua"

//-------------------------------------------------------------------------
// lua api stuff
//-------------------------------------------------------------------------

class LuaApi
{
protected:
    LuaApi(string& t, string& s, string& c)
    {
        type = t;
        name = s;
        chunk = c;
    }

public:
    virtual ~LuaApi() { }
    virtual const BaseApi* get_base() const = 0;

public:
    string type;
    string name;
    string chunk;
};

static vector<const BaseApi*> base_api;
static vector<LuaApi*> lua_api;

//-------------------------------------------------------------------------
// ips option stuff
//-------------------------------------------------------------------------

class IpsLuaApi : public LuaApi
{
public:
    IpsLuaApi(string& t, string& n, string& c, unsigned v);

    const BaseApi* get_base() const
    { return &api.base; }

public:
    IpsApi api;
};

IpsLuaApi::IpsLuaApi(string& t, string& s, string& c, unsigned v) : LuaApi(t, s, c)
{
    extern const IpsApi* ips_luajit;
    api = *ips_luajit;
    api.base.name = name.c_str();
    api.base.version = v;
}

//-------------------------------------------------------------------------
// log api stuff
//-------------------------------------------------------------------------

class LogLuaApi : public LuaApi
{
public:
    LogLuaApi(string& t, string& n, string& c, unsigned v);

    const BaseApi* get_base() const
    { return &api.base; }

public:
    LogApi api;
};

LogLuaApi::LogLuaApi(string& t, string& s, string& c, unsigned v) : LuaApi(t, s, c)
{
    extern const LogApi* log_luajit;
    api = *log_luajit;
    api.base.name = name.c_str();
    api.base.version = v;
}

//-------------------------------------------------------------------------
// lua foo
//-------------------------------------------------------------------------

static bool get_field(lua_State* L, const char* key, int& value)
{
    lua_pushstring(L, key);
    lua_gettable(L, -2);

    if ( !lua_isnumber(L, -1) )
    {
        ParseWarning(WARN_SCRIPTS, "%s is not a number", key);
        lua_pop(L, 1);
        return false;
    }

    value = (long)lua_tonumber(L, -1);
    lua_pop(L, 1);

    return true;
}

static bool get_field(lua_State* L, const char* key, string& value)
{
    lua_pushstring(L, key);
    lua_gettable(L, -2);

    if ( !lua_isstring(L, -1) )
    {
        ParseWarning(WARN_SCRIPTS, "%s is not a string", key);
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
        ParseWarning(WARN_SCRIPTS, "can't load %s: %s", f, lua_tostring(L, -1));
        return;
    }

    // lua_pcall() pops the function so we push it again first
    // if this is a copy, there must be a cheaper alternative
    lua_pushvalue(L, -1);

    if ( lua_pcall(L, 0, 0, 0) )
    {
        ParseWarning(WARN_SCRIPTS, "can't init %s: %s", f, lua_tostring(L, -1));
        return;
    }

    lua_getglobal(L, "plugin");

    if ( !lua_istable(L, -1) )
    {
        ParseWarning(WARN_SCRIPTS, "can't get plugin from %s", f);
        return;
    }

    int ver = -1;
    string type, name, chunk;

    if ( !get_field(L, "type", type) )
    {
        ParseError("missing plugin type %s = '%s'", f, type.c_str());
        return;
    }

    if ( type != "ips_option" && type != "logger" )
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

    if ( type == "ips_option" )
        lua_api.push_back(new IpsLuaApi(type, name, chunk, ver));
    else
        lua_api.push_back(new LogLuaApi(type, name, chunk, ver));

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

const BaseApi** ScriptManager::get_plugins()
{
    base_api.clear();

    for ( auto p : lua_api )
        base_api.push_back(p->get_base());

    base_api.push_back(nullptr);

    return (const BaseApi**)&base_api[0];
}

void ScriptManager::release_scripts()
{
    for ( auto p : lua_api )
        if ( p )
            delete p;

    lua_api.clear();
    base_api.clear();
}

string* ScriptManager::get_chunk(const char* key)
{
    for ( auto p : lua_api )
        if ( p->name == key )
            return &p->chunk;

    return nullptr;
}

