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
// lua_ref.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lua_ref.h"

#include "lua.h"

// leave 2 items on the stack (key, ref table)
// uses 4 slots
static inline void create_registry_table(lua_State* L, void* p)
{
    // key = address of object
    lua_pushlightuserdata(L, p);
    // dup key
    lua_pushvalue(L, -1);
    // get: registry[key]
    lua_gettable(L, LUA_REGISTRYINDEX);

    if ( lua_isnil(L, -1) )
    {
        // remove nil
        lua_pop(L, 1);
        // ref = new ref table
        lua_newtable(L);
        // dup key
        lua_pushvalue(L, -2);
        // dup ref
        lua_pushvalue(L, -2);
        // set: registry[key] = ref
        lua_settable(L, LUA_REGISTRYINDEX);
    }
}

// leaves 1 item on the stack (ref table or nil)
// uses 1 slot
static inline void lookup_registry_table(lua_State* L, void* p)
{
    lua_pushlightuserdata(L, p);
    lua_gettable(L, LUA_REGISTRYINDEX);
}

// leaves nothing extra on the stack
// uses 1 slot
static inline void add_entry(lua_State* L, const char* key, int index, int table)
{
    lua_pushvalue(L, index);
    lua_setfield(L, table, key);
}

// leaves nothing extra on the stack
// uses 1 slot
static inline void remove_entry(lua_State* L, const char* key, int table)
{
    lua_pushnil(L);
    lua_setfield(L, table, key);
}

namespace Lua
{
void add_ref(lua_State* L, void* owner, const char* key, int ref_index)
{
    Lua::ManageStack ms(L, 4);
    create_registry_table(L, owner);
    add_entry(L, key, ref_index, lua_gettop(L));
}

void remove_ref(lua_State* L, void* owner, const char* key)
{
    Lua::ManageStack ms(L, 2);
    lookup_registry_table(L, owner);
    if ( !lua_isnil(L, -1) )
        remove_entry(L, key, lua_gettop(L));
}

void remove_refs(lua_State* L, void* owner)
{
    Lua::ManageStack ms(L, 2);
    lua_pushlightuserdata(L, owner);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);
}
}
