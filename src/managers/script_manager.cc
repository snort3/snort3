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
// script_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "script_manager.h"

#include <sys/stat.h>

#include "framework/ips_option.h"
#include "framework/logger.h"
#include "framework/lua_api.h"
#include "helpers/directory.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "lua/lua_util.h"

#ifdef PIGLET
#include "piglet/piglet_manager.h"
#endif

using namespace snort;
using namespace std;

// FIXIT-P this approach results in N * K lua states where
// N ::= number of instances of script + args and
// K ::= number of threads
// change to create K lua states here for each script + args
// and change LuaJit*() to get reference to thread states
// ultimately should look into changing detection engine to
// keep just one copy of rule option + args

#define script_pattern "*.lua"

//-------------------------------------------------------------------------
// lua api stuff
//-------------------------------------------------------------------------

static vector<const BaseApi*> base_api;
static vector<LuaApi*> lua_api;

//-------------------------------------------------------------------------
// ips option stuff
//-------------------------------------------------------------------------

class IpsLuaApi : public LuaApi
{
public:
    IpsLuaApi(string& n, string& c, unsigned v);

    const BaseApi* get_base() const override
    { return &api.base; }

public:
    IpsApi api;
    static const char* type;
};

const char* IpsLuaApi::type = "ips_option";

IpsLuaApi::IpsLuaApi(string& s, string& c, unsigned v) : LuaApi(s, c)
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
    LogLuaApi(string& n, string& c, unsigned v);

    const BaseApi* get_base() const override
    { return &api.base; }

public:
    LogApi api;
    static const char* type;
};

const char* LogLuaApi::type = "logger";

LogLuaApi::LogLuaApi(string& s, string& c, unsigned v) : LuaApi(s, c)
{
    extern const LogApi* log_luajit;
    api = *log_luajit;
    api.base.name = name.c_str();
    api.base.version = v;
}

//-------------------------------------------------------------------------
// lua foo
//-------------------------------------------------------------------------

// FIXIT-L could be a template
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

// FIXIT-L move to helpers/lua
static int dump(lua_State*, const void* p, size_t sz, void* ud)
{
    string* s = static_cast<string*>(ud);
    s->append(static_cast<const char*>(p), sz);
    return 0;
}

// FIXIT-L use Lua::State to wrap lua_State
static void load_script(const char* f)
{
    Lua::State lua;
    auto L = lua.get_ptr();

    // Set this now so that dependent dofile()s can work correctly
    Lua::set_script_dir(L, SCRIPT_DIR_VARNAME, f);

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

    if ( type == IpsLuaApi::type )
        lua_api.push_back(new IpsLuaApi(name, chunk, ver));

    else if ( type == LogLuaApi::type )
        lua_api.push_back(new LogLuaApi(name, chunk, ver));

#ifdef PIGLET
    else if ( type == "piglet" )
        Piglet::Manager::add_chunk(f, name, chunk);
#endif

    else
    {
        ParseError("unknown plugin type in %s = '%s'", f, type.c_str());
        return;
    }
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void ScriptManager::load_scripts(const std::vector<std::string>& paths)
{
    struct stat s;

    if ( paths.empty() )
        return;

    for ( const auto& path : paths )
    {
        size_t pos = path.find_first_not_of(':');

        while ( pos != std::string::npos )
        {
            size_t end_pos = path.find_first_of(':', pos);

            std::string d = path.substr(
                pos, (end_pos == std::string::npos) ? end_pos : end_pos - pos);

            pos = ( end_pos == std::string::npos ) ? end_pos : end_pos + 1;

            if ( d.empty() )
                continue;

            if ( stat(d.c_str(), &s) )
                continue;

            if ( s.st_mode & S_IFDIR )
            {
                Directory dir(d.c_str(), script_pattern);
                const char* f;
                while ( (f = dir.next()) )
                    load_script(f);
            }

            else
                load_script(d.c_str());
        }
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

