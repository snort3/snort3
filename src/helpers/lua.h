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

// methods and templates for the C++ / LuaJIT interface

#include <string>
#include <luajit-2.0/lua.hpp>

namespace Lua
{

// Resource manager for lua_State
class State
{
public:
    State(bool openlibs = true);
    ~State();

    State(State&) = delete;
    State(State&&) = delete;

    lua_State* get_ptr()
    { return state; }

private:
    lua_State* state;
};

// Stack maintainer for lua_State
class ManageStack
{
public:
    ManageStack(lua_State* L, int extra = 0);

    ManageStack(ManageStack&) = delete;
    ManageStack(ManageStack&&) = delete;

    ~ManageStack();

private:
    lua_State* state;
    int top;
};


// FIXIT-L: Should go in its own file
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

// Call from Lua context only
template<typename T>
T** check_userdata(lua_State* L, const char* type, int arg)
{
    return static_cast<T**>(
        const_cast<void*>(
            luaL_checkudata(L, arg, type)
            )
        );
}

// Call from Lua context only
template<typename T>
T* get_userdata(lua_State* L, const char* type, int arg)
{ return *check_userdata<T>(L, type, arg); }
}
}

#endif

