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
// lua.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_H
#define LUA_H

#include <luajit-2.0/lua.hpp>

namespace Lua
{
class Handle;

class State
{
public:
    State(bool = true);
    ~State();

    Handle get_handle();

private:
    lua_State* _state;
};

class Handle
{
public:
    Handle(lua_State* state) :
        _state { state }
    { }

    lua_State* get_state()
    { return _state; }

private:
    lua_State* _state;
};

namespace Interface
{
struct Library
{
    const char* tname;
    const luaL_reg* methods;
    const luaL_reg* metamethods;
};

void register_lib(lua_State*, const struct Library*);

template<typename T>
T** new_userdata(lua_State* L)
{ return (T**)lua_newuserdata(L, sizeof(T*)); }

template<typename T>
T** create_userdata(lua_State* L, const char* type)
{
    auto t = new_userdata<T>(L);
    luaL_getmetatable(L, type);
    lua_setmetatable(L, -2);
    return t;
}

template<typename T>
T** check_userdata(lua_State* L, const char* type, int arg)
{
    return static_cast<T**>(
        const_cast<void*>(
            luaL_checkudata(L, arg, type)
            )
        );
}

template<typename T>
T* get_userdata(lua_State* L, const char* type, int arg)
{ return *check_userdata<T>(L, type, arg); }
}
}

#endif

