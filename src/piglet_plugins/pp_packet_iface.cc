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
// pp_packet_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_packet_iface.h"

#include <luajit-2.0/lua.hpp>

#include "lua/lua_arg.h"
#include "lua/lua_table.h"
#include "protocols/packet.h"
#include "pp_decode_data_iface.h"
#include "pp_flow_iface.h"
#include "pp_raw_buffer_iface.h"
#include "pp_daq_pkthdr_iface.h"

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = PacketIface.create(L);

            // (Optional) first argument is raw packet
            if ( arg.count )
            {
                auto& rb = RawBufferIface.get(L, 1);
                self.pkt = reinterpret_cast<const uint8_t*>(rb.data());
            }

            // (Optional) second argument is daq header
            if ( arg.count > 1 )
                self.pkth = &DAQHeaderIface.get(L, 2);

            return 1;
        }
    },
    {
        "set_decode_data",
        [](lua_State* L)
        {
            auto& self = PacketIface.get(L, 1);
            auto& dd = DecodeDataIface.get(L, 2);

            self.ptrs = dd;

            return 0;
        }
    },
    {
        "set_data",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = PacketIface.get(L, 1);
            size_t offset = arg.check_size(2);
            size_t size = arg.check_size(3);

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

            return 0;
        }
    },
    {
        "get",
        [](lua_State* L)
        {
            auto& self = PacketIface.get(L);
            lua_newtable(L);

            Lua::Table table(L, lua_gettop(L));

            table.set_field("packet_flags", self.packet_flags);
            table.set_field("xtradata_mask", self.xtradata_mask);
            table.set_field("proto_bits", self.proto_bits);
            table.set_field(
                "application_protocol_ordinal",
                self.application_protocol_ordinal
            );

            table.set_field("alt_dsize", self.alt_dsize);
            table.set_field("num_layers", self.num_layers);
            table.set_field("iplist_id", self.iplist_id);
            table.set_field("user_policy_id", self.user_policy_id);
            table.set_field("ps_proto", self.ps_proto);

            return 1;
        }
    },
    {
        "set",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = PacketIface.get(L, 1);

            arg.check_table(2);

            Lua::Table table(L, 2);
            table.get_field("packet_flags", self.packet_flags);
            table.get_field("xtradata_mask", self.xtradata_mask);
            table.get_field("proto_bits", self.proto_bits);
            table.get_field(
                "application_protocol_ordinal",
                self.application_protocol_ordinal
            );

            table.get_field("alt_dsize", self.alt_dsize);
            table.get_field("num_layers", self.num_layers);
            table.get_field("iplist_id", self.iplist_id);
            table.get_field("user_policy_id", self.user_policy_id);
            table.get_field("ps_proto", self.ps_proto);

            return 0;
        }
    },
    {
        "set_pkt",
        [](lua_State* L)
        {
            auto& self = PacketIface.get(L, 1);
            auto& rb = RawBufferIface.get(L, 2);

            self.pkt = reinterpret_cast<const uint8_t*>(rb.data());

            return 0;
        }
    },
    {
        "set_daq",
        [](lua_State* L)
        {
            auto& self = PacketIface.get(L, 1);
            auto& daq = DAQHeaderIface.get(L, 2);

            self.pkth = &daq;

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
            auto& self = PacketIface.get(L);
            lua_pushfstring(L, "%s@%p", PacketIface.name, &self);
            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            PacketIface.destroy(L);
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<Packet> PacketIface =
{
    "Packet",
    methods,
    metamethods
};
