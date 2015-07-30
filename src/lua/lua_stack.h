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
// lua_stack.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_STACK_H
#define LUA_STACK_H

#include <string>
#include <type_traits>

#include <luajit-2.0/lua.hpp>

#include "lua_util.h"

namespace Lua
{
template<typename T, typename Integral = void>
struct Stack {};

template<typename T>
struct Stack<T, typename std::enable_if<std::is_integral<T>::value>::type>
{
    static inline void push(lua_State* L, const T& v)
    { lua_pushnumber(L, v); }

    static inline T get(lua_State* L, int n)
    { return lua_tonumber(L, n); }

    static inline constexpr int type()
    { return LUA_TNUMBER; }
};

template<>
struct Stack<const char*>
{
    static inline void push(lua_State* L, const char* v)
    { lua_pushstring(L, v); }

    static inline const char* get(lua_State* L, int n)
    { return lua_tostring(L, n); }

    static inline constexpr int type()
    { return LUA_TSTRING; }
};

template<>
struct Stack<std::string>
{
    static inline void push(lua_State* L, const std::string& v)
    { lua_pushlstring(L, v.c_str(), v.size()); }

    static inline std::string get(lua_State* L, int n)
    {
        size_t len = 0;
        const char* s = lua_tolstring(L, n, &len);
        return std::string(s, len);
    }

    static inline constexpr int type()
    { return LUA_TSTRING; }
};

template<>
struct Stack<bool>
{
    static inline void push(lua_State* L, const bool& v)
    { lua_pushboolean(L, v); }

    static inline bool get(lua_State* L, int n)
    { return lua_toboolean(L, n); }

    static inline constexpr int type()
    { return LUA_TBOOLEAN; }
};
}
#endif
