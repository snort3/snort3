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
// pp_decode_data_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_decode_data_iface.h"

#include <luajit-2.0/lua.hpp>

#include "framework/decode_data.h"
#include "lua/lua_arg.h"
#include "lua/lua_table.h"
#include "protocols/ipv4.h"

#include "pp_raw_buffer_iface.h"

static void set_fields(lua_State* L, int tindex, DecodeData& dd)
{
    Lua::Table table(L, tindex);

    table.get_field("sp", dd.sp);
    table.get_field("dp", dd.dp);
    table.get_field("decode_flags", dd.decode_flags);

    uint8_t pkt_type = 0;
    table.get_field("type", pkt_type);
    dd.type = static_cast<PktType>(pkt_type);
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = DecodeDataIface.create(L);

            if ( arg.count )
            {
                arg.check_table(1);
                set_fields(L, 1, self);
            }

            return 1;
        }
    },
    {
        "reset",
        [](lua_State* L)
        {
            auto& self = DecodeDataIface.get(L);
            self.reset();

            return 0;
        }
    },
    {
        "set",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = DecodeDataIface.get(L, 1);

            arg.check_table(2);
            set_fields(L, 2, self);

            return 0;
        }
    },
    {
        "get",
        [](lua_State* L)
        {
            auto& self = DecodeDataIface.get(L);
            lua_newtable(L);

            Lua::Table table(L, lua_gettop(L));
            table.set_field("sp", self.sp);
            table.set_field("dp", self.dp);
            table.set_field("decode_flags", self.decode_flags);
            table.set_field(
                "type",
                static_cast<uint8_t>(self.type)
            );

            return 1;
        }
    },
    // FIXIT-L: Need a more sophisticated interface to decode data ip_api
    {
        "set_ipv4_hdr",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = DecodeDataIface.get(L, 1);
            auto& rb = RawBufferIface.get(L, 2);
            size_t offset = arg.opt_size(3, 0, rb.size());

            // Need enough room for an IPv4 header
            if ( (rb.size() - offset) < sizeof(IP4Hdr) )
                luaL_error(
                    L, "need %d bytes, got %d",
                    sizeof(IP4Hdr), rb.size()
                );

            self.ip_api.set(
                reinterpret_cast<const IP4Hdr*>(rb.data() + offset));

            return 0;
        }
    },
    // FIXIT-L: add access to mplsHdr field
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        {
            auto& self = DecodeDataIface.get(L);
            lua_pushfstring(L, "%s@%p", DecodeDataIface.name, &self);
            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            DecodeDataIface.destroy(L);
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<DecodeData> DecodeDataIface =
{
    "DecodeData",
    methods,
    metamethods
};
