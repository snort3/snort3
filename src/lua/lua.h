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
// lua.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_H
#define LUA_H

// methods and templates for the C++ / LuaJIT interface

#include <lua.hpp>

#include "main/snort_types.h"

namespace Lua
{

// Resource manager for lua_State
class State
{
public:
    State(bool openlibs = true);
    ~State();

    State(State&) = delete;

    // Enable move constructor
    State(State&& other);

    lua_State* get_ptr()
    { return state; }

    operator lua_State*()
    { return get_ptr(); }

private:
    lua_State* state;
};

// Stack maintainer for lua_State
class SO_PUBLIC ManageStack
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

}
#endif

