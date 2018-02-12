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

// lua_test_common.cc author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_TEST_COMMON_H
#define LUA_TEST_COMMON_H

//#include <utility>
#include <lua.hpp>

inline void l_end_lua_state(lua_State*& L_ptr)
{
    if ( L_ptr )
    {
        lua_close(L_ptr);
        L_ptr = nullptr;
    }
}

inline void l_reset_lua_state(lua_State*& L_ptr)
{
    l_end_lua_state(L_ptr);
    L_ptr = luaL_newstate();
    luaL_openlibs(L_ptr);
}

template<typename T, size_t N>
inline constexpr size_t sizeofArray(T (&)[N])
{ return N; }

#endif
