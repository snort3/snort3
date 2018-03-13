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
// pp_codec_data_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_codec_data_iface.h"

#include "framework/codec.h"
#include "lua/lua_arg.h"

using namespace snort;

static void set_fields(lua_State* L, int tindex, CodecData& self)
{
    Lua::Table table(L, tindex);

    table.get_field("next_prot_id", reinterpret_cast<uint16_t&>(self.next_prot_id));
    table.get_field("lyr_len", self.lyr_len);
    table.get_field("invalid_bytes", self.invalid_bytes);
    table.get_field("proto_bits", self.proto_bits);
    table.get_field("codec_flags", self.codec_flags);
    table.get_field("ip_layer_cnt", self.ip_layer_cnt);
    table.get_field("ip6_extension_count", self.ip6_extension_count);
    table.get_field("curr_ip6_extension", self.curr_ip6_extension);
    table.get_field("ip6_csum_proto", reinterpret_cast<uint8_t&>(self.ip6_csum_proto));
}

static void get_fields(lua_State* L, int tindex, CodecData& self)
{
    Lua::Table table(L, tindex);

    table.set_field("next_prot_id", static_cast<uint16_t>(self.next_prot_id));
    table.set_field("lyr_len", self.lyr_len);
    table.set_field("invalid_bytes", self.invalid_bytes);
    table.set_field("proto_bits", self.proto_bits);
    table.set_field("codec_flags", self.codec_flags);
    table.set_field("ip_layer_cnt", self.ip_layer_cnt);
    table.set_field("ip6_extension_count", self.ip6_extension_count);
    table.set_field("curr_ip6_extension", self.curr_ip6_extension);
    table.set_field("ip6_csum_proto", static_cast<uint8_t>(self.ip6_csum_proto));
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = CodecDataIface.create(L, ProtocolId::ETHERTYPE_NOT_SET);
            memset(&self, 0, sizeof(self));

            if ( args[1].is_table() )
                args[1].check_table(set_fields, self);
            else if ( args[1].is_size() )
            {
                //  FIXIT-L can check_size limit size to short?
                unsigned int tmp = args[1].check_size();
                if(tmp > UINT16_MAX)
                    self.next_prot_id = ProtocolId::ETHERTYPE_NOT_SET;
                else
                    self.next_prot_id = (ProtocolId)args[1].check_size();
            }

            return 1;
        }
    },
    {
        "get",
        [](lua_State* L)
        { return CodecDataIface.default_getter(L, get_fields); }
    },
    {
        "set",
        [](lua_State* L)
        { return CodecDataIface.default_setter(L, set_fields); }
    },
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        { return CodecDataIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        { return CodecDataIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<CodecData> CodecDataIface =
{
    "CodecData",
    methods,
    metamethods
};
