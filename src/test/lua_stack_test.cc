//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <string>
#include <luajit-2.0/lua.hpp>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#include <check.h>

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include "lua_test_common.h"
#include "lua/lua_stack.h"

static lua_State* L = nullptr;

static void LuaCleanup(void)
{ l_end_lua_state(L); }

static void LuaFixture(void)
{ l_reset_lua_state(L); }

START_TEST(test_signed)
{
    bool b;
    int k;

    // Test get
    lua_pushinteger(L, 3);
    {
        auto r = Lua::Stack<int>::get(L, -1);
        ck_assert_int_eq(r, 3);
    }
    lua_pop(L, 1);

    // Test push
    int j = 4;
    Lua::Stack<int>::push(L, j);
    {
        lua_Integer l = lua_tointeger(L, -1);
        ck_assert_int_eq(l, j);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushinteger(L, 1);
    {
        b = Lua::Stack<int>::validate(L, -1);
        ck_assert(b);
    }
    lua_pop(L, 1);

    // Test validate
    k = 0;
    lua_pushinteger(L, 5);
    {
        b = Lua::Stack<int>::validate(L, -1, k);
        ck_assert_int_eq(k, 5);
        ck_assert(b);
    }
    lua_pop(L, 1);

    // Test validate false
    k = 7;
    lua_pushnil(L);
    {
        b = Lua::Stack<int>::validate(L, -1, k);
        ck_assert_int_eq(k, 7);
        ck_assert(!b);
    }
    lua_pop(L, 1);
}
END_TEST

START_TEST(test_unsigned)
{
    bool b;
    unsigned short k;

    // Test get
    lua_pushinteger(L, 3);
    {
        auto r = Lua::Stack<unsigned short>::get(L, -1);
        ck_assert_int_eq(r, 3);
    }
    lua_pop(L, 1);

    // Test push
    unsigned short j = 4;
    Lua::Stack<unsigned short>::push(L, j);
    {
        lua_Integer l = lua_tointeger(L, -1);
        ck_assert_int_eq(l, j);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushinteger(L, 1);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1);
        ck_assert(b);
    }
    lua_pop(L, 1);

    // Test validate
    k = 0;
    lua_pushinteger(L, 5);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1, k);
        ck_assert_int_eq(k, 5);
        ck_assert(b);
    }
    lua_pop(L, 1);

    // Test validate false
    k = 7;
    lua_pushnil(L);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1, k);
        ck_assert_int_eq(k, 7);
        ck_assert(!b);
    }
    lua_pop(L, 1);
    lua_pushinteger(L, -1);
    {
        b = Lua::Stack<unsigned short>::validate(L, -1, k);
        ck_assert_int_eq(k, 7);
        ck_assert(!b);
    }
    lua_pop(L, 1);
}
END_TEST

START_TEST(test_cstring)
{
    bool b;
    const char* s;
    size_t len;

    // Test type
    ck_assert_int_eq(Lua::Stack<const char*>::type(), LUA_TSTRING);

    // Test get
    s = nullptr;
    lua_pushstring(L, "foo");
    {
        s = Lua::Stack<const char*>::get(L, -1);
        ck_assert_str_eq(s, "foo");
    }
    lua_pop(L, 1);

    // Test get w/length
    s = nullptr;
    len = 0;
    lua_pushlstring(L, "f\0b", 3);
    {
        s = Lua::Stack<const char*>::get(L, -1, len);
        ck_assert_uint_eq(len, 3);
        l_assert_strn_eq(s, "f\0b", len);
    }
    lua_pop(L, 1);

    // Test push
    s = "foo";
    Lua::Stack<const char*>::push(L, s);
    {
        s = lua_tostring(L, -1);
        ck_assert_str_eq(s, "foo");
    }
    lua_pop(L, 1);

    len = 0;
    s = "f\0o";
    Lua::Stack<const char*>::push(L, s);
    {
        s = lua_tolstring(L, -1, &len);
        ck_assert_str_eq(s, "f");
        ck_assert_uint_eq(len, 1);
    }
    lua_pop(L, 1);

    // Test push w/length
    len = 0;
    s = "f\0b";
    Lua::Stack<const char*>::push(L, s, 3);
    {
        s = lua_tolstring(L, -1, &len);
        ck_assert_uint_eq(len, 3);
        l_assert_strn_eq(s, "f\0b", len);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushstring(L, "foo");
    {
        b = Lua::Stack<const char*>::validate(L, -1);
        ck_assert(b);
    }
    lua_pop(L, 1);

    // Test validate
    len = 0;
    s = "foo";
    lua_pushstring(L, s);
    {
        s = nullptr;
        b = Lua::Stack<const char*>::validate(L, -1, s);
        ck_assert(b);
        ck_assert_str_eq(s, "foo");
    }
    lua_pop(L, 1);

    // Test validate w/length
    len = 0;
    s = "f\0b";
    lua_pushlstring(L, s, 3);
    {
        s = nullptr;
        b = Lua::Stack<const char*>::validate(L, -1, s, len);
        ck_assert(b);
        l_assert_strn_eq(s, "f\0b", 3);
    }
    lua_pop(L, 1);

    // Test invalid
    s = nullptr;
    lua_pushnil(L);
    {
        b = Lua::Stack<const char*>::validate(L, -1, s);
        ck_assert(!s);
        ck_assert(!b);
    }
    lua_pop(L, 1);

    s = nullptr;
    lua_pushnil(L);
    {
        b = Lua::Stack<const char*>::validate(L, -1, s, len);
        ck_assert(!s);
        ck_assert(!b);
    }
    lua_pop(L, 1);
}
END_TEST

START_TEST(test_string)
{
    bool b;
    const char* cs;
    std::string s;
    size_t len;

    // Test type
    ck_assert_int_eq(Lua::Stack<std::string>::type(), LUA_TSTRING);

    // Test get
    lua_pushstring(L, "foo");
    {
        s = Lua::Stack<std::string>::get(L, -1);
        ck_assert(s == "foo");
    }
    lua_pop(L, 1);

    // Test get w/zeros
    lua_pushlstring(L, "f\0b", 3);
    {
        s = Lua::Stack<std::string>::get(L, -1);
        ck_assert(s.length() == 3);
        l_assert_strn_eq(s.c_str(), "f\0b", 3);
    }
    lua_pop(L, 1);

    // Test push
    s = "foo";
    Lua::Stack<std::string>::push(L, s);
    {
        cs = lua_tostring(L, -1);
        ck_assert_str_eq(cs, "foo");
    }
    lua_pop(L, 1);

    len = 0;
    s.assign("f\0b", 3);
    Lua::Stack<std::string>::push(L, s);
    {
        cs = lua_tolstring(L, -1, &len);
        ck_assert_uint_eq(len, 3);
        l_assert_strn_eq(cs, "f\0b", len);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushstring(L, "foo");
    {
        b = Lua::Stack<std::string>::validate(L, -1);
        ck_assert(b);
    }
    lua_pop(L, 1);

    // Test validate
    lua_pushstring(L, "foo");
    {
        b = Lua::Stack<std::string>::validate(L, -1, s);
        ck_assert(b);
        ck_assert(s == "foo");
    }
    lua_pop(L, 1);

    lua_pushlstring(L, "f\0o", 3);
    {
        b = Lua::Stack<std::string>::validate(L, -1, s);
        ck_assert(b);
        ck_assert_uint_eq(s.length(), 3);
        l_assert_strn_eq(s.c_str(), "f\0o", 3);
    }
    lua_pop(L, 1);

    // Test invalid
    lua_pushnil(L);
    {
        b = Lua::Stack<std::string>::validate(L, -1, s);
        ck_assert(!b);
    }
    lua_pop(L, 1);
}
END_TEST

START_TEST(test_bool)
{
    bool b, v;

    // Test get
    lua_pushboolean(L, true);
    {
        v = Lua::Stack<bool>::get(L, -1);
        ck_assert(v);
    }
    lua_pop(L, 1);

    // Test push
    Lua::Stack<bool>::push(L, true);
    {
        v = lua_toboolean(L, -1);
        ck_assert(v);
    }
    lua_pop(L, 1);

    // Test validate, no output
    lua_pushboolean(L, true);
    {
        b = Lua::Stack<bool>::validate(L, -1);
        ck_assert(b);
    }
    lua_pop(L, 1);

    // Test validate
    lua_pushboolean(L, true);
    {
        b = Lua::Stack<bool>::validate(L, -1, v);
        ck_assert(b);
        ck_assert(v);
    }
    lua_pop(L, 1);

    // Test invalid
    lua_pushnil(L);
    {
        b = Lua::Stack<bool>::validate(L, -1, v);
        ck_assert(!b);
    }
    lua_pop(L, 1);
}
END_TEST

Suite* TEST_SUITE_lua_stack(void)
{
    Suite* ps = suite_create("lua_stack");

    TCase* tc = tcase_create("lua_stack");
    tcase_add_unchecked_fixture(tc, LuaFixture, LuaCleanup);
    tcase_add_test(tc, test_signed);
    tcase_add_test(tc, test_unsigned);
    tcase_add_test(tc, test_cstring);
    tcase_add_test(tc, test_string);
    tcase_add_test(tc, test_bool);
    suite_add_tcase(ps, tc);

    return ps;
}
