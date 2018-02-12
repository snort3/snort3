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
// lua_stack.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_STACK_H
#define LUA_STACK_H

#include <lua.hpp>

#include <string>

namespace Lua
{
template<typename T>
inline constexpr bool IsInteger()
{ return std::is_integral<T>::value && !std::is_same<T, bool>::value; }

template<typename T, typename Integral = void, typename Unsigned = void>
struct Stack {};

// unsigned integer
template<typename T>
struct Stack<T, typename std::enable_if<IsInteger<T>()>::type,
    typename std::enable_if<std::is_unsigned<T>::value>::type>
{
    static void push(lua_State* L, const T& v)
    { lua_pushinteger(L, v); }

    static T get(lua_State* L, int n)
    { return lua_tointeger(L, n); }

    static constexpr int type()
    { return LUA_TNUMBER; }

    static bool validate(lua_State* L, int n, T& v)
    {
        if ( lua_type(L, n) != type() )
            return false;

        lua_Integer tmp = lua_tointeger(L, n);
        if ( tmp < 0 )
            return false;

        v = tmp;
        return true;
    }

    static bool validate(lua_State* L, int n)
    {
        T v;
        return validate(L, n, v);
    }
};

// integer
template<typename T>
struct Stack<T, typename std::enable_if<IsInteger<T>()>::type,
    typename std::enable_if<!std::is_unsigned<T>::value>::type>
{
    static void push(lua_State* L, const T& v)
    { lua_pushinteger(L, v); }

    static T get(lua_State* L, int n)
    { return lua_tointeger(L, n); }

    static constexpr int type()
    { return LUA_TNUMBER; }

    static bool validate(lua_State* L, int n, T& v)
    {
        if ( lua_type(L, n) != type() )
            return false;

        v = lua_tointeger(L, n);
        return true;
    }

    static bool validate(lua_State* L, int n)
    {
        T v;
        return validate(L, n, v);
    }
};

// default
template<typename T>
struct Stack<T, typename std::enable_if<!IsInteger<T>()>::type>
{
    static void push(lua_State*, T);
    static void push(lua_State*, T, size_t);

    static T get(lua_State*, int);
    static T get(lua_State*, int, size_t&);

    static constexpr int type();

    static bool validate(lua_State* L, int n, T& v)
    {
        if ( lua_type(L, n) != type() )
            return false;

        v = get(L, n);
        return true;
    }

    static bool validate(lua_State* L, int n)
    {
        T v;
        return validate(L, n, v);
    }

    static bool validate(lua_State*, int, T&, size_t&);
};

// const char*
template<>
inline void Stack<const char*>::push(lua_State* L, const char* s)
{ lua_pushstring(L, s); }

template<>
inline void Stack<const char*>::push(lua_State* L, const char* s, size_t len)
{ lua_pushlstring(L, s, len); }

template<>
inline const char* Stack<const char*>::get(lua_State* L, int n)
{ return lua_tostring(L, n); }

template<>
inline const char* Stack<const char*>::get(lua_State* L, int n, size_t& len)
{ return lua_tolstring(L, n, &len); }

template<>
inline constexpr int Stack<const char*>::type()
{ return LUA_TSTRING; }

template<>
inline bool Stack<const char*>::validate(
    lua_State* L, int n, const char*& v, size_t& len)
{
    if ( lua_type(L, n) != type() )
        return false;

    v = get(L, n, len);
    return true;
}

// string
template<>
inline void Stack<std::string>::push(lua_State* L, std::string s)
{ lua_pushlstring(L, s.c_str(), s.length()); }

template<>
inline std::string Stack<std::string>::get(lua_State* L, int n)
{
    size_t len = 0;
    const char* s = lua_tolstring(L, n, &len);
    return std::string(s, len);
}

template<>
inline constexpr int Stack<std::string>::type()
{ return LUA_TSTRING; }

// bool
template<>
inline void Stack<bool>::push(lua_State* L, bool v)
{ lua_pushboolean(L, v); }

template<>
inline bool Stack<bool>::get(lua_State* L, int n)
{ return lua_toboolean(L, n); }

template<>
inline constexpr int Stack<bool>::type()
{ return LUA_TBOOLEAN; }
}
#endif
