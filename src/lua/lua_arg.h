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
// lua_arg.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_ARG_H
#define LUA_ARG_H

#include <luajit-2.0/lua.hpp>

namespace Lua
{
// FIXIT-M: generate better oob error messages
struct Arg
{
    lua_State* L;
    int count;

    inline bool exists(int n)
    { return !lua_isnone(L, n); }

    inline void check_type(int n, int type)
    { luaL_checktype(L, n, type); }

    // Types
    inline bool is_type(int n, int type) 
    { return lua_type(L, n) == type; }

    inline bool is_number(int n)
    { return is_type(n, LUA_TNUMBER); }

    inline bool is_string(int n)
    { return is_type(n, LUA_TSTRING); }

    inline bool is_table(int n)
    { return is_type(n, LUA_TTABLE); }

    inline bool is_boolean(int n)
    { return is_type(n, LUA_TBOOLEAN); }

    // Table
    inline void check_table(int n)
    { check_type(n, LUA_TTABLE); }

    // Boolean
    inline bool check_boolean(int n)
    {
        check_type(n, LUA_TBOOLEAN);
        return lua_toboolean(L, n);
    }

    inline bool opt_boolean(int n, bool d = false)
    {
        if ( is_boolean(n) )
            return check_boolean(n);

        return d;
    }

    // String
    inline const char* check_string(int n, size_t* len = nullptr)
    {
        check_type(n, LUA_TSTRING);
        return lua_tolstring(L, n, len);
    }

    inline const char* opt_string(int n, const char* d, size_t* len = nullptr)
    {
        if ( is_string(n) )
            return check_string(n, len);

        return d;
    }

    // Integers
    inline lua_Integer check_int(int n)
    {
        check_type(n, LUA_TNUMBER);
        return lua_tointeger(L, n);
    }

    inline lua_Integer check_int(int n, lua_Integer min, lua_Integer max)
    {
        auto v = check_int(n);
        luaL_argcheck(L, ((v >= min) && (v <= max)), n, "oob");
        return v;
    }

    inline lua_Integer opt_int(int n, lua_Integer d = 0)
    {
        if ( is_number(n) )
            return check_int(n);

        return d;
    }

    inline lua_Integer opt_int(
        int n, lua_Integer d, lua_Integer min, lua_Integer max)
    {
        auto v = opt_int(n, d);
        luaL_argcheck(L, ((v >= min) && (v <= max)), n, "oob");
        return v;
    }

    inline unsigned check_size(int n)
    {
        auto v = check_int(n);
        luaL_argcheck(L, (v >= 0), n, "oob");
        return v;
    }

    inline unsigned check_size(int n, unsigned max)
    {
        auto v = check_size(n);
        luaL_argcheck(L, (v <= max), n, "oob");
        return v;
    }

    inline unsigned check_size(int n, unsigned min, unsigned max)
    {
        auto v = check_size(n, max);
        luaL_argcheck(L, (v >= min), n, "oob");
        return v;
    }

    inline unsigned opt_size(int n, unsigned d = 0)
    {
        if ( is_number(n) )
            return check_size(n);

        return d;
    }

    inline unsigned opt_size(int n, unsigned d, unsigned max)
    {
        auto v = opt_size(n, d);
        luaL_argcheck(L, (v <= max), n, "oob");
        return v;
    }

    inline unsigned opt_size(int n, unsigned d, unsigned min, unsigned max)
    {
        auto v = opt_size(n, d, max);
        luaL_argcheck(L, (v >= min), n, "oob");
        return v;
    }

    Arg(lua_State* state) : L(state)
    { count = lua_gettop(L); }
};
}
#endif
