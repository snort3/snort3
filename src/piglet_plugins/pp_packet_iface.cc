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
// pp_packet_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_packet_iface.h"

#include "lua/lua_arg.h"
#include "protocols/packet.h"

#include "pp_daq_pkthdr_iface.h"
#include "pp_decode_data_iface.h"
#include "pp_flow_iface.h"
#include "pp_raw_buffer_iface.h"

using namespace snort;

static void set_fields(lua_State* L, int tindex, Packet& self)
{
    Lua::Table table(L, tindex);

    table.get_field("packet_flags", self.packet_flags);
    table.get_field("xtradata_mask", self.xtradata_mask);
    table.get_field("proto_bits", self.proto_bits);
    table.get_field("alt_dsize", self.alt_dsize);
    table.get_field("num_layers", self.num_layers);
    table.get_field("iplist_id", self.iplist_id);
    table.set_field("user_inspection_policy_id", self.user_inspection_policy_id);
    table.set_field("user_ips_policy_id", self.user_ips_policy_id);
    table.set_field("user_network_policy_id", self.user_network_policy_id);
}

static void get_fields(lua_State* L, int tindex, Packet& self)
{
    Lua::Table table(L, tindex);

    table.set_field("packet_flags", self.packet_flags);
    table.set_field("xtradata_mask", self.xtradata_mask);
    table.set_field("proto_bits", self.proto_bits);
    table.set_field("alt_dsize", self.alt_dsize);
    table.set_field("num_layers", self.num_layers);
    table.set_field("iplist_id", self.iplist_id);
    table.set_field("user_inspection_policy_id", self.user_inspection_policy_id);
    table.set_field("user_ips_policy_id", self.user_ips_policy_id);
    table.set_field("user_network_policy_id", self.user_network_policy_id);
}

static void set(lua_State* L, Packet& self, Lua::Args& args, int start)
{
    for ( int i = start; i <= args.count; i++ )
    {
        if ( args[i].is_string() )
        {
            size_t len = 0;
            const char* s = args[i].check_string(len);
            auto& rb = RawBufferIface.create(L, s, len);
            self.pkt = get_data(rb);
            Lua::add_ref(L, &self, "pkt", lua_gettop(L));
            lua_pop(L, 1);
        }
        else if ( args[i].is_size() )
        {
            size_t sz = args[i].check_size();
            auto& rb = RawBufferIface.create(L, sz, '\0');
            self.pkt = get_data(rb);
            Lua::add_ref(L, &self, "pkt", lua_gettop(L));
            lua_pop(L, 1);
        }
        else if ( args[i].is_table() )
        {
            args[i].check_table(set_fields, self);
        }
        else if ( RawBufferIface.is(L, i) )
        {
            self.pkt = get_data(RawBufferIface.get(L, i));
            Lua::add_ref(L, &self, "pkt", i);
        }
        else if ( DAQHeaderIface.is(L, i) )
        {
            self.pkth = &DAQHeaderIface.get(L, i);
            Lua::add_ref(L, &self, "pkth", i);
        }
        else
        {
            luaL_argerror(L, i,
                "expected string or unsigned or table or RawBuffer or DAQHeader");
        }
    }
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = PacketIface.create(L);
            self.reset();

            set(L, self, args, 1);

            return 1;
        }
    },
    {
        "set_decode_data",
        [](lua_State* L)
        {
            PacketIface.get(L, 1).ptrs = DecodeDataIface.get(L, 2);
            return 0;
        }
    },
    {
        "set_data",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = PacketIface.get(L, 1);
            size_t offset = args[2].check_size();
            size_t size = args[3].check_size();

            self.data = self.pkt + offset;
            self.dsize = size;

            return 0;
        }
    },
    {
        "set_flow",
        [](lua_State* L)
        {
            auto& self = PacketIface.get(L, 1);
            auto& flow = FlowIface.get(L, 2);

            self.flow = &flow;
            Lua::add_ref(L, &self, "flow", 2);

            return 0;
        }
    },
    {
        "get",
        [](lua_State* L)
        { return PacketIface.default_getter(L, get_fields); }
    },
    {
        "set",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = PacketIface.get(L, 1);

            set(L, self, args, 2);

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
        { return PacketIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        { return PacketIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<Packet> PacketIface =
{
    "Packet",
    methods,
    metamethods
};
