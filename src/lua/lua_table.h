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
// lua_table.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_TABLE_H
#define LUA_TABLE_H

#include <vector>

#include "lua_stack.h"

namespace Lua
{
struct Table
{
    lua_State* L;
    int index;

    template<typename T>
    inline bool get(int n, T& v)
    {
        if ( lua_type(L, n) == Stack<T>::type() )
        {
            v = Stack<T>::get(L, n);
            return true;
        }

        return false;
    }

    inline bool set_field_from_stack(const char* k, int v)
    {
        lua_pushstring(L, k);
        lua_pushvalue(L, v);
        lua_settable(L, index);
        return true;
    }

    inline bool raw_set_field_from_stack(const char* k, int v)
    {
        lua_pushstring(L, k);
        lua_pushvalue(L, v);
        lua_rawset(L, index);
        return true;
    }

    inline bool get_field_to_stack(const char* k)
    {
        lua_getfield(L, index, k);
        return true;
    }

    template<typename T>
    inline bool get_field(const char* k, T& v)
    {
        lua_getfield(L, index, k);
        bool rv = get(-1, v);
        lua_pop(L, 1);
        return rv;
    }

    template<typename T>
    inline bool get_default(const char* k, T& v, T d = 0)
    {
        if ( !get_field<T>(k, v) )
        {
            v = d;
            return false;
        }

        return true;
    }

    template<typename T>
    inline bool raw_get_field(const char* k, T& v)
    {
        lua_pushstring(L, k);
        lua_rawget(L, index);
        bool rv = get(-1, v);
        lua_pop(L, 1);
        return rv;
    }

    template<typename T>
    bool raw_get_field(int i, T& v)
    {
        lua_rawgeti(L, index, i);
        bool rv = get(-1, v);
        lua_pop(L, 1);
        return rv;
    }

    template<typename T>
    bool set_field(const char* k, const T& v)
    {
        Stack<T>::push(L, v);
        lua_setfield(L, index, k);
        return false;
    }

    template<typename T>
    bool raw_set_field(const char* k, const T& v)
    {
        lua_pushstring(L, k);
        Stack<T>::push(L, v);
        lua_rawset(L, index);
        return false;
    }

    template<typename T>
    bool raw_set_field(int i, const T& v)
    {
        Stack<T>::push(L, v);
        lua_rawseti(L, index, i);
        return true;
    }

    Table(lua_State* state, int t) : L(state), index(t) { }
};

template<typename T>
inline void fill_table_from_vector(lua_State* L, int tindex, std::vector<T>& vec)
{
    Table table(L, tindex);
    int i = 0;
    for ( auto v : vec )
        table.raw_set_field(++i, v);
}
}
#endif
