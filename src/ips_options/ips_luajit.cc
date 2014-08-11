/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "ips_luajit.h"

#include <lua.hpp>

#include "managers/ips_manager.h"
#include "hash/sfhashfcn.h"
#include "parser/parser.h"
#include "framework/cursor.h"
#include "time/profiler.h"

using namespace std;

// FIXIT need to register these perf stats
static THREAD_LOCAL ProfileStats luajitPerfStats;

static const char* opt_init = "init";
static const char* opt_eval = "eval";

//-------------------------------------------------------------------------
// luajit ffi stuff
//-------------------------------------------------------------------------

struct Buffer
{
    const char* type;
    const uint8_t* data;
    unsigned len;
};

extern "C" {
// ensure Lua can link with this
const Buffer* get_buffer();
}

static THREAD_LOCAL Cursor* cursor;
static THREAD_LOCAL Buffer buf;

//namespace snort_ffi
//{
const Buffer* get_buffer()
{
    assert(cursor);
    buf.type = cursor->get_name();
    buf.data = cursor->start();
    buf.len = cursor->length();
    return &buf;
}
//};

//-------------------------------------------------------------------------
// lua implementation stuff
//-------------------------------------------------------------------------

struct Loader
{
    Loader(string& s) : chunk(s) { done = false; };
    string& chunk;
    bool done;
};

const char* load(lua_State*, void* ud, size_t* size)
{
    Loader* ldr = (Loader*)ud;

    if ( ldr->done )
    {
        *size = 0;
        return nullptr;
    }
    ldr->done = true;
    *size = ldr->chunk.size();
    return ldr->chunk.c_str();
}

static void init_lua(
    lua_State*& L, string& chunk, const char* name, string& args)
{
    L = luaL_newstate();
    luaL_openlibs(L);

    Loader ldr(chunk);

    // first load the chunk
    if ( lua_load(L, load, &ldr, name) )
        ParseError("%s luajit failed to load chunk %s", 
            name, lua_tostring(L, -1));

    // now exec the chunk to define functions etc in L
    if ( lua_pcall(L, 0, 0, 0) )
        ParseError("%s luajit failed to init chunk %s", 
            name, lua_tostring(L, -1));

    // load the args table 
    if ( luaL_loadstring(L, args.c_str()) )
        ParseError("%s luajit failed to load args %s", 
            name, lua_tostring(L, -1));

    // exec the args table to define it in L
    if ( lua_pcall(L, 0, 0, 0) )
        ParseError("%s luajit failed to init args %s", 
            name, lua_tostring(L, -1));

    // exec the init func if defined
    lua_getglobal(L, opt_init);

    if ( !lua_isfunction(L, -1) )
        return;

    if ( lua_pcall(L, 0, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        ParseError("%s %s", name, err);
    }
    // string is an error message
    if ( lua_isstring(L, -1) )
    {
        const char* err = lua_tostring(L, -1);
        ParseError("%s %s", name, err);
    }
    // bool is the result
    if ( !lua_toboolean(L, -1) )
    {
        ParseError("%s init() returned false", name);
    }
    // initialization complete
    lua_pop(L, 1);
}

static void term_lua(lua_State*& L)
{
    lua_close(L);
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter luajit_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "luajit arguments" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

LuaJitModule::LuaJitModule(const char* name) : Module(name, luajit_params)
{ }

ProfileStats* LuaJitModule::get_profile() const
{ return &luajitPerfStats; }

bool LuaJitModule::begin(const char*, int, SnortConfig*)
{
    args.clear();
    return true;
}

bool LuaJitModule::set(const char*, Value& v, SnortConfig*)
{
    args = v.get_string();
    return true;
}

//-------------------------------------------------------------------------
// option stuff
//-------------------------------------------------------------------------

LuaJitOption::LuaJitOption(
    const char* name, string& chunk, LuaJitModule* mod)
    : IpsOption(name)
{
    string args = mod->args;

    // if args not empty, it has to be a quoted string
    // so remove enclosing quotes
    if ( args.size() > 1 )
    {
        args.erase(0, 1);
        args.erase(args.size()-1);
    }

    // create an args table with any rule options
    config = "args = { ";
    config += args;
    config += "}";

    unsigned max = get_instance_max();

    lua = new lua_State*[max];

    for ( unsigned i = 0; i < max; ++i )
        init_lua(lua[i], chunk, name, config);
}

LuaJitOption::~LuaJitOption()
{
    unsigned max = get_instance_max();

    for ( unsigned i = 0; i < max; ++i )
        term_lua(lua[i]);

    delete[] lua;
}

uint32_t LuaJitOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    mix_str(a,b,c,get_name());
    mix_str(a,b,c,config.c_str());
    final(a,b,c);
    return c;
}

bool LuaJitOption::operator==(const IpsOption& ips) const
{
    LuaJitOption& rhs = (LuaJitOption&)ips;

    if ( strcmp(get_name(), rhs.get_name()) )
        return false;

    if ( config != rhs.config )
        return false;

    return true;
}

int LuaJitOption::eval(Cursor& c, Packet*)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(luajitPerfStats);

    cursor = &c;

    lua_State* L = lua[get_instance_id()];
    lua_getglobal(L, opt_eval);

    if ( lua_pcall(L, 0, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        ErrorMessage("%s\n", err);
        MODULE_PROFILE_END(luajitPerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }
    bool result = lua_toboolean(L, -1);
    lua_pop(L, 1);

    int ret = result ? DETECTION_OPTION_MATCH : DETECTION_OPTION_NO_MATCH;
    MODULE_PROFILE_END(luajitPerfStats);

    return ret;
}

