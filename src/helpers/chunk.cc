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
// chunk.cc author Russ Combs <rucombs@cisco.com>

#include "chunk.h"

#include <luajit-2.0/lua.hpp>

#include "managers/ips_manager.h"
#include "hash/sfhashfcn.h"
#include "parser/parser.h"
#include "framework/cursor.h"
#include "time/profiler.h"
#include "lua/lua.h"

using namespace std;

#define opt_init "init"

//-------------------------------------------------------------------------
// lua stuff
//-------------------------------------------------------------------------

struct Loader
{
    Loader(string& s) : chunk(s) { done = false; }
    string& chunk;
    bool done;
};

static const char* ldchunk(lua_State*, void* ud, size_t* size)
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

void init_chunk(
    lua_State*& L, string& chunk, const char* name, string& args)
{
    L = luaL_newstate();
    Lua::ManageStack ms(L);

    luaL_openlibs(L);

    Loader ldr(chunk);

    // first load the chunk
    if ( lua_load(L, ldchunk, &ldr, name) )
    {
        ParseError("%s luajit failed to load chunk %s", name, lua_tostring(L, -1));
        return;
    }

    // now exec the chunk to define functions etc in L
    if ( lua_pcall(L, 0, 0, 0) )
    {
        ParseError("%s luajit failed to init chunk %s", name, lua_tostring(L, -1));
        return;
    }

    // load the args table
    if ( luaL_loadstring(L, args.c_str()) )
    {
        ParseError("%s luajit failed to load args %s", name, lua_tostring(L, -1));
        return;
    }

    // exec the args table to define it in L
    if ( lua_pcall(L, 0, 0, 0) )
    {
        ParseError("%s luajit failed to init args %s", name, lua_tostring(L, -1));
        return;
    }

    // exec the init func if defined
    lua_getglobal(L, opt_init);

    if ( !lua_isfunction(L, -1) )
        return;

    if ( lua_pcall(L, 0, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        ParseError("%s %s", name, err);
        return;
    }
    // string is an error message
    if ( lua_isstring(L, -1) )
    {
        const char* err = lua_tostring(L, -1);
        ParseError("%s %s", name, err);
        return;
    }
    // bool is the result
    if ( !lua_toboolean(L, -1) )
    {
        ParseError("%s init() returned false", name);
        return;
    }
}

void term_chunk(lua_State*& L)
{
    lua_close(L);
}

