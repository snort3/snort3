//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// lua_stack_test.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <string>

#include "catch/snort_catch.h"

#include "lua_test_common.h"
#include "lua/lua_stack.h"

static lua_State* L = nullptr;

static void test_signed()
{
    bool b;
    int k;

    // Test get
    lua_pushinteger(L, 3);
    {
        auto r = Lua::Stack<int>::get(L, -1);
        CHECK((r == 3));
    }
    lua_pop(L, 1);

    // Test push
    int j = 4;
    Lua::Stack<int>::push(L, j);
    {
        lua_Integer l = lua_tointeger(L, -1);
        CHECK(l == j);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushinteger(L, 1);
    {
        b = Lua::Stack<int>::validate(L, -1);
        CHECK(b);
    }
    lua_pop(L, 1);

    // Test validate
    k = 0;
    lua_pushinteger(L, 5);
    {
        b = Lua::Stack<int>::validate(L, -1, k);
        CHECK((k == 5));
        CHECK(b);
    }
    lua_pop(L, 1);

    // Test validate false
    k = 7;
    lua_pushnil(L);
    {
        b = Lua::Stack<int>::validate(L, -1, k);
        CHECK((k == 7));
        CHECK(!b);
    }
    lua_pop(L, 1);
}

static void test_unsigned()
{
    bool b;
    unsigned short k;

    // Test get
    lua_pushinteger(L, 3);
    {
        auto r = Lua::Stack<unsigned short>::get(L, -1);
        CHECK((r == 3));
    }
    lua_pop(L, 1);

    // Test push
    unsigned short j = 4;
    Lua::Stack<unsigned short>::push(L, j);
    {
        lua_Integer l = lua_tointeger(L, -1);
        CHECK(l == j);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushinteger(L, 1);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1);
        CHECK(b);
    }
    lua_pop(L, 1);

    // Test validate
    k = 0;
    lua_pushinteger(L, 5);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1, k);
        CHECK((k == 5));
        CHECK(b);
    }
    lua_pop(L, 1);

    // Test validate false
    k = 7;
    lua_pushnil(L);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1, k);
        CHECK((k == 7));
        CHECK(!b);
    }
    lua_pop(L, 1);
    lua_pushinteger(L, -1);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1, k);
        CHECK((k == 7));
        CHECK(!b);
    }
    lua_pop(L, 1);
}

static void test_cstring()
{
    bool b;
    const char* s;
    size_t len;

    // Test type
    CHECK(Lua::Stack<const char*>::type() == LUA_TSTRING);

    // Test get
    s = nullptr;
    lua_pushstring(L, "foo");
    {
        s = Lua::Stack<const char*>::get(L, -1);
        CHECK(!strcmp(s, "foo"));
    }
    lua_pop(L, 1);

    // Test get w/length
    s = nullptr;
    len = 0;
    lua_pushlstring(L, "f\0b", 3);
    {
        s = Lua::Stack<const char*>::get(L, -1, len);
        CHECK((len == 3));
        CHECK(!strncmp(s, "f\0b", len));
    }
    lua_pop(L, 1);

    // Test push
    s = "foo";
    Lua::Stack<const char*>::push(L, s);
    {
        s = lua_tostring(L, -1);
        CHECK(!strcmp(s, "foo"));
    }
    lua_pop(L, 1);

    len = 0;
    s = "f\0o";
    Lua::Stack<const char*>::push(L, s);
    {
        s = lua_tolstring(L, -1, &len);
        CHECK(!strcmp(s, "f"));
        CHECK(len == 1);
    }
    lua_pop(L, 1);

    // Test push w/length
    len = 0;
    s = "f\0b";
    Lua::Stack<const char*>::push(L, s, 3);
    {
        s = lua_tolstring(L, -1, &len);
        CHECK((len == 3));
        CHECK(!strncmp(s, "f\0b", len));
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushstring(L, "foo");
    {
        b = Lua::Stack<const char*>::validate(L, -1);
        CHECK(b);
    }
    lua_pop(L, 1);

    // Test validate
    len = 0;
    s = "foo";
    lua_pushstring(L, s);
    {
        s = nullptr;
        b = Lua::Stack<const char*>::validate(L, -1, s);
        CHECK(b);
        REQUIRE(s);
        CHECK(!strcmp(s, "foo"));
    }
    lua_pop(L, 1);

    // Test validate w/length
    len = 0;
    s = "f\0b";
    lua_pushlstring(L, s, 3);
    {
        s = nullptr;
        b = Lua::Stack<const char*>::validate(L, -1, s, len);
        CHECK(b);
        REQUIRE(s);
        CHECK(!strncmp(s, "f\0b", 3));
    }
    lua_pop(L, 1);

    // Test invalid
    s = nullptr;
    lua_pushnil(L);
    {
        b = Lua::Stack<const char*>::validate(L, -1, s);
        CHECK(!s);
        CHECK(!b);
    }
    lua_pop(L, 1);

    s = nullptr;
    lua_pushnil(L);
    {
        b = Lua::Stack<const char*>::validate(L, -1, s, len);
        CHECK(!s);
        CHECK(!b);
    }
    lua_pop(L, 1);
}

static void test_string()
{
    bool b;
    const char* cs;
    std::string s;
    size_t len;

    // Test type
    CHECK(Lua::Stack<std::string>::type() == LUA_TSTRING);

    // Test get
    lua_pushstring(L, "foo");
    {
        s = Lua::Stack<std::string>::get(L, -1);
        CHECK(s == "foo");
    }
    lua_pop(L, 1);

    // Test get w/zeros
    lua_pushlstring(L, "f\0b", 3);
    {
        s = Lua::Stack<std::string>::get(L, -1);
        CHECK((s.length() == 3));
        CHECK(!strncmp(s.c_str(), "f\0b", 3));
    }
    lua_pop(L, 1);

    // Test push
    s = "foo";
    Lua::Stack<std::string>::push(L, s);
    {
        cs = lua_tostring(L, -1);
        CHECK(!strcmp(cs, "foo"));
    }
    lua_pop(L, 1);

    len = 0;
    s.assign("f\0b", 3);
    Lua::Stack<std::string>::push(L, s);
    {
        cs = lua_tolstring(L, -1, &len);
        CHECK((len == 3));
        CHECK(!strncmp(cs, "f\0b", len));
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushstring(L, "foo");
    {
        b = Lua::Stack<std::string>::validate(L, -1);
        CHECK(b);
    }
    lua_pop(L, 1);

    // Test validate
    lua_pushstring(L, "foo");
    {
        b = Lua::Stack<std::string>::validate(L, -1, s);
        CHECK(b);
        CHECK(s == "foo");
    }
    lua_pop(L, 1);

    lua_pushlstring(L, "f\0o", 3);
    {
        b = Lua::Stack<std::string>::validate(L, -1, s);
        CHECK(b);
        CHECK((s.length() == 3));
        CHECK(!strncmp(s.c_str(), "f\0o", 3));
    }
    lua_pop(L, 1);

    // Test invalid
    lua_pushnil(L);
    {
        b = Lua::Stack<std::string>::validate(L, -1, s);
        CHECK(!b);
    }
    lua_pop(L, 1);
}

static void test_bool()
{
    bool b, v;

    // Test get
    lua_pushboolean(L, true);
    {
        v = Lua::Stack<bool>::get(L, -1);
        CHECK(v);
    }
    lua_pop(L, 1);

    // Test push
    Lua::Stack<bool>::push(L, true);
    {
        v = lua_toboolean(L, -1);
        CHECK(v);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushboolean(L, true);
    {
        b = Lua::Stack<bool>::validate(L, -1);
        CHECK(b);
    }
    lua_pop(L, 1);

    // Test validate
    lua_pushboolean(L, true);
    {
        b = Lua::Stack<bool>::validate(L, -1, v);
        CHECK(b);
        CHECK(v);
    }
    lua_pop(L, 1);

    // Test invalid
    lua_pushnil(L);
    {
        b = Lua::Stack<bool>::validate(L, -1, v);
        CHECK(!b);
    }
    lua_pop(L, 1);
}

TEST_CASE("lua_stack", "[lua_stack]")
{
    l_reset_lua_state(L);

    SECTION("signed")
    {
        test_signed();
    }
    SECTION("unsigned")
    {
        test_unsigned();
    }
    SECTION("cstring")
    {
        test_cstring();
    }
    SECTION("string")
    {
        test_string();
    }
    SECTION("bool")
    {
        test_bool();
    }
    l_end_lua_state(L);
}
