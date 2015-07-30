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
// pp_codec_data_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_codec_data_iface.h"

#include <luajit-2.0/lua.hpp>

#include "framework/codec.h"
#include "lua/lua_table.h"
#include "lua/lua_arg.h"

static void set_fields(lua_State* L, int tindex, CodecData& cd)
{
    Lua::Table table(L, tindex);

    table.get_field("next_prot_id", cd.next_prot_id);
    table.get_field("lyr_len", cd.lyr_len);
    table.get_field("invalid_bytes", cd.invalid_bytes);
    table.get_field("proto_bits", cd.proto_bits);
    table.get_field("codec_flags", cd.codec_flags);
    table.get_field("ip_layer_cnt", cd.ip_layer_cnt);
    table.get_field("ip6_extension_count", cd.ip6_extension_count);
    table.get_field("curr_ip6_extension", cd.curr_ip6_extension);
    table.get_field("ip6_csum_proto", cd.ip6_csum_proto);
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = CodecDataIface.create(L, 0);

            if ( arg.count )
            {
                if ( arg.is_table(1) )
                    set_fields(L, 1, self);
                else
                    self.next_prot_id = arg.check_size(1);
            }

            return 1;
        }
    },
    {
        "get",
        [](lua_State* L)
        {
            auto& self = CodecDataIface.get(L);
            lua_newtable(L);

            Lua::Table table(L, lua_gettop(L));

            table.set_field("next_prot_id", self.next_prot_id);
            table.set_field("lyr_len", self.lyr_len);
            table.set_field("invalid_bytes", self.invalid_bytes);
            table.set_field("proto_bits", self.proto_bits);
            table.set_field("codec_flags", self.codec_flags);
            table.set_field("ip_layer_cnt", self.ip_layer_cnt);
            table.set_field("ip6_extension_count", self.ip6_extension_count);
            table.set_field("curr_ip6_extension", self.curr_ip6_extension);
            table.set_field("ip6_csum_proto", self.ip6_csum_proto);

            return 1;
        }
    },
    {
        "set",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = CodecDataIface.get(L, 1);

            arg.check_table(2);
            set_fields(L, 2, self);

            return 0;
        }
    },
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        {
            auto& self = CodecDataIface.get(L);
            lua_pushfstring(L, "%s@%p", CodecDataIface.name, &self);

            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            CodecDataIface.destroy(L);
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<CodecData> CodecDataIface =
{
    "CodecData",
    methods,
    metamethods
};
