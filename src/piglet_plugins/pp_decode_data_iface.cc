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
// pp_decode_data_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_decode_data_iface.h"

#include "framework/decode_data.h"
#include "lua/lua_arg.h"

#include "pp_ip_api_iface.h"
#include "pp_raw_buffer_iface.h"

// FIXIT-M add Internet Header objects
// FIXIT-M add Enum Interface
static void set_fields(lua_State* L, int tindex, DecodeData& self)
{
    Lua::Table table(L, tindex);

    table.get_field("sp", self.sp);
    table.get_field("dp", self.dp);
    table.get_field("decode_flags", self.decode_flags);

    uint8_t pkt_type = 0;
    table.get_field("type", pkt_type);
    self.type = static_cast<PktType>(pkt_type);
}

static void get_fields(lua_State* L, int tindex, DecodeData& self)
{
    Lua::Table table(L, tindex);

    table.set_field("sp", self.sp);
    table.set_field("dp", self.dp);
    table.set_field("decode_flags", self.decode_flags);
    table.set_field("type", static_cast<uint8_t>(self.type));
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = DecodeDataIface.create(L);
            self.reset();

            args[1].opt_table(set_fields, self);

            return 1;
        }
    },
    {
        "reset",
        [](lua_State* L)
        {
            DecodeDataIface.get(L).reset();
            return 0;
        }
    },
    {
        "set",
        [](lua_State* L)
        { return DecodeDataIface.default_setter(L, set_fields); }
    },
    {
        "get",
        [](lua_State* L)
        { return DecodeDataIface.default_getter(L, get_fields); }
    },
    {
        // Return a reference to the IpApi attached to DecodeData
        "get_ip_api",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = DecodeDataIface.get(L, 1);

            auto ip_api_handle = IpApiIface.allocate(L);

            // *pointer* to DecodeData::ip_api;
            *ip_api_handle = &self.ip_api;

            // Make sure the decode data doesn't run out from under the ref
            Lua::add_ref(L, *ip_api_handle, "decode_data", lua_gettop(L));

            return 1;
        }
    },
    // FIXIT-L add access to mplsHdr field
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        { return DecodeDataIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        { return DecodeDataIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<DecodeData> DecodeDataIface =
{
    "DecodeData",
    methods,
    metamethods
};
