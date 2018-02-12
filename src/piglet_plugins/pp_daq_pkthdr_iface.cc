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

#include "pp_daq_pkthdr_iface.h"

#include <daq_common.h>

#include <cstring>

#include "lua/lua_arg.h"

static void set_fields(lua_State* L, int tindex, struct _daq_pkthdr& self)
{
    Lua::Table table(L, tindex);

    table.get_field("caplen", self.caplen);
    table.get_field("pktlen", self.pktlen);
    table.get_field("ingress_index", self.ingress_index);
    table.get_field("egress_index", self.egress_index);
    table.get_field("ingress_group", self.ingress_group);
    table.get_field("egress_group", self.egress_group);
    table.get_field("flags", self.flags);
    table.get_field("opaque", self.opaque);
    table.get_field("flow_id", self.flow_id);
    table.get_field("address_space_id", self.address_space_id);

    // FIXIT-L do we want to be able to set the priv_ptr field?
}

static void get_fields(lua_State* L, int tindex, struct _daq_pkthdr& self)
{
    Lua::Table table(L, tindex);

    table.set_field("caplen", self.caplen);
    table.set_field("pktlen", self.pktlen);
    table.set_field("ingress_index", self.ingress_index);
    table.set_field("egress_index", self.egress_index);
    table.set_field("ingress_group", self.ingress_group);
    table.set_field("egress_group", self.egress_group);
    table.set_field("flags", self.flags);
    table.set_field("opaque", self.opaque);
    table.set_field("flow_id", self.flow_id);
    table.set_field("address_space_id", self.address_space_id);
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = DAQHeaderIface.create(L);
            memset(&self, 0, sizeof(self));

            args[1].opt_table(set_fields, self);

            return 1;
        }
    },
    {
        "get",
        [](lua_State* L)
        { return DAQHeaderIface.default_getter(L, get_fields); }
    },
    {
        "set",
        [](lua_State* L)
        { return DAQHeaderIface.default_setter(L, set_fields); }
    },
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        { return DAQHeaderIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        { return DAQHeaderIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<_daq_pkthdr> DAQHeaderIface =
{
    "DAQHeader",
    methods,
    metamethods
};
