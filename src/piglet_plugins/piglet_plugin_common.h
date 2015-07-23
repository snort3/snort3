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
// piglet_plugin_common.h author Joel Cornett <jocornet@cisco.com>

#ifndef PIGLET_PLUGIN_COMMON_H
#define PIGLET_PLUGIN_COMMON_H

// Utils for working with the Lua C API and
// interfaces for exposing some common structs to Lua.

#include <daq.h>
#include <luajit-2.0/lua.hpp>

#include <limits>
#include <vector>

#include "events/event.h"
#include "detection/signature.h"
#include "framework/codec.h"
#include "helpers/lua.h"
#include "protocols/packet.h"

namespace PigletCommon
{
using namespace Lua;

namespace Util
{

// Call from Lua context only
template<typename T>
T* regurgitate_instance(lua_State* L, int index)
{
    int up = lua_upvalueindex(index);

    luaL_checktype(L, up, LUA_TLIGHTUSERDATA);

    return static_cast<T*>(
        const_cast<void*>(lua_topointer(L, up))
        );
}

template<typename T>
void register_wrapper(
    lua_State* L, lua_CFunction wrapper, const char* name, T* instance)
{
    lua_pushlightuserdata(L, static_cast<void*>(instance));
    lua_pushcclosure(L, wrapper, 1);
    lua_setglobal(L, name);
}

// Call from Lua context only
template<typename T>
int tostring(lua_State* L, const char* type)
{
    auto o = Interface::get_userdata<T>(L, type, 1);
    lua_pushfstring(L, "%s@0x%p", type, o);
    return 1;
}

template<typename T>
void register_instance_lib(
    lua_State* L, const luaL_reg* methods, const char* tname, T* instance)
{
    Lua::ManageStack ms(L, 4);
    int table, inst;
    const luaL_reg* entry = methods;

    lua_newtable(L);
    table = lua_gettop(L);

    lua_pushlightuserdata(L, static_cast<void*>(instance));
    inst = lua_gettop(L);

    while ( entry->func )
    {
        lua_pushvalue(L, inst);
        lua_pushcclosure(L, entry->func, 1);
        lua_setfield(L, table, entry->name);
        entry++;
    }

    lua_pop(L, 1);
    lua_setglobal(L, tname);
}
} // namespace Util

namespace RawBufferLib
{
using type = std::vector<char>;
extern const char* tname;
extern const struct Lua::Interface::Library lib;
} // namespace RawBufferLib

namespace DecodeDataLib
{
using type = DecodeData;
extern const char* tname;
extern const struct Lua::Interface::Library lib;
} // namespace DecodeData

namespace PacketLib
{
using type = Packet;
extern const char* tname;
extern const struct Lua::Interface::Library lib;
} // namespace PacketLib

struct _daq_pkthdr* cooked_daq_pkthdr(uint32_t, uint32_t = 0);

// Call from Lua context only
size_t check_size_param(
    lua_State*,
    int,
    size_t = std::numeric_limits<size_t>::max()
);

// Call from Lua context only
size_t opt_size_param(
    lua_State*,
    int,
    lua_Integer,
    size_t = std::numeric_limits<size_t>::max()
);

} // namespace PigletCommon
#endif

