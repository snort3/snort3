//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// lua_detector_util.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_DETECTOR_UTIL_H
#define LUA_DETECTOR_UTIL_H

// encapsulate Lua interface boilerplate to get sane, identical behavior across users

#include <cassert>
#include <lua.hpp>

template<typename T>
struct UserData
{
    T* ptr;

    T* operator->()
    { return ptr; }

    const T* operator->() const
    { return ptr; }

    operator T*() const
    { return ptr; }

    operator T*()
    { return ptr; }

    static UserData<T>* push(lua_State* L, const char* const meta, T* ptr = nullptr)
    {
        int type_size = sizeof(UserData<T>);
        auto ud = static_cast<UserData<T>*>(lua_newuserdata(L, type_size));
        assert(ud);
        ud->ptr = ptr;
        luaL_getmetatable(L, meta);
        lua_setmetatable(L, -2);
        return ud;
    }

    static UserData<T>* check(lua_State* L, const char* const meta, int n)
    {
        luaL_checktype(L, n, LUA_TUSERDATA);
        auto ud = static_cast<UserData<T>*>(luaL_checkudata(L, n, meta));
        assert(ud);
        return ud;
    }
};

#endif

