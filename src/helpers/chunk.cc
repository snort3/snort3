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
// chunk.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "chunk.h"

#include "log/messages.h"
#include "lua/lua.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace std;

#define opt_init "init"

//-------------------------------------------------------------------------
// lua stuff
//-------------------------------------------------------------------------

bool init_chunk(
    lua_State* L, string& chunk, const char* name, string& args)
{
    Lua::ManageStack ms(L, 1);

    if ( luaL_loadbuffer(L, chunk.c_str(), chunk.size(), name) )
    {
        snort::ParseError("%s luajit failed to load chunk %s", name, lua_tostring(L, -1));
        return false;
    }

    // now exec the chunk to define functions etc in L
    if ( lua_pcall(L, 0, 0, 0) )
    {
        snort::ParseError("%s luajit failed to init chunk %s", name, lua_tostring(L, -1));
        return false;
    }

    // load the args table
    if ( luaL_dostring(L, args.c_str()) )
    {
        snort::ParseError("%s luajit failed to init args %s", name, lua_tostring(L, -1));
        return false;
    }

    // exec the init func if defined
    lua_getglobal(L, opt_init);

    // init func is not defined
    if ( !lua_isfunction(L, -1) )
        return true;

    if ( lua_pcall(L, 0, 1, 0) || lua_type(L, -1) == LUA_TSTRING )
        snort::ParseError("%s %s", name, lua_tostring(L, -1));

    else if ( !lua_toboolean(L, -1) )
        snort::ParseError("%s init() returned false", name);

    else
        return true;

    return false;
}

#ifdef UNIT_TEST
TEST_CASE( "chunk initialization", "[chunk]" )
{
    Lua::State lua(true);

    string test_chunk = "function init() return true end";
    string test_args_table = "args = { a = 1, b = 2 }";
    const char* test_name = "test_alert_luajit";

    SECTION( "normal initialization" )
    {
        CHECK((init_chunk(lua, test_chunk, test_name, test_args_table) == true));
    }

    SECTION( "init() edge cases" )
    {
        SECTION( "init is not a function" )
        {
            string test_init_not_a_function_chunk = "init = 1";
            CHECK(
                (init_chunk(lua, test_init_not_a_function_chunk,
                    test_name, test_args_table) == true)
            );
        }

        SECTION( "init is not defined" )
        {
            string test_init_not_defined_chunk;
            CHECK(
                (init_chunk(lua, test_init_not_defined_chunk,
                    test_name, test_args_table) == true)
            );
        }
    }

    SECTION( "initialization errors" )
    {
        SECTION( "malformed chunk" )
        {
            string test_malformed_chunk = "function init()";
            CHECK_FALSE(
                (init_chunk(lua, test_malformed_chunk, test_name, test_args_table) == true)
            );
        }

        SECTION( "malformed args table" )
        {
            string test_malformed_args_table = "args = {";
            CHECK_FALSE(
                (init_chunk(lua, test_chunk, test_name, test_malformed_args_table) == true)
            );
        }

        SECTION( "init returns false" )
        {
            string test_init_returns_false_chunk =
                "function init() return false end";

            CHECK_FALSE(
                (init_chunk(lua, test_init_returns_false_chunk,
                    test_name, test_args_table) == true)
            );
        }
    }
}
#endif

