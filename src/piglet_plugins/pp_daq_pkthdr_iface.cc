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
// pp_daq_pkthdr_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_daq_pkthdr_iface.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <luajit-2.0/lua.hpp>

#include "lua/lua_table.h"

extern "C" {
#include <daq.h>
}

static void daq_header_set(lua_State* L, int tindex, struct _daq_pkthdr& daq)
{
    Lua::Table table(L, tindex);

    table.get_field("caplen", daq.caplen);
    table.get_field("pktlen", daq.pktlen);
    table.get_field("ingress_index", daq.ingress_index);
    table.get_field("egress_index", daq.egress_index);
    table.get_field("ingress_group", daq.ingress_group);
    table.get_field("egress_group", daq.egress_group);
    table.get_field("flags", daq.flags);
    table.get_field("opaque", daq.opaque);
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
#ifdef HAVE_DAQ_FLOW_ID
    table.get_field("flow_id", daq.flow_id);
#endif
    table.get_field("address_space_id", daq.address_space_id);
#endif

    // FIXIT-L: Do we want to be able to set the priv_ptr field?
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            auto& self = DAQHeaderIface.create(L);

            // If we had an initializer argument, there
            // will be two items on the stack now
            if ( lua_gettop(L) > 1 )
            {
                luaL_checktype(L, 1, LUA_TTABLE);
                daq_header_set(L, 1, self);
            }

            return 1;
        }
    },
    {
        "get",
        [](lua_State* L)
        {
            auto& self = DAQHeaderIface.get(L);
            lua_newtable(L);

            Lua::Table table(L, lua_gettop(L));

            table.set_field("caplen", self.caplen);
            table.set_field("pktlen", self.pktlen);
            table.set_field("ingress_index", self.ingress_index);
            table.set_field("egress_index", self.egress_index);
            table.set_field("ingress_group", self.ingress_group);
            table.set_field("egress_group", self.egress_group);
            table.set_field("flags", self.flags);
            table.set_field("opaque", self.opaque);
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
#ifdef HAVE_DAQ_FLOW_ID
            table.set_field("flow_id", self.flow_id);
#endif
            table.set_field("address_space_id", self.address_space_id);
#endif

            // FIXIT-L: Do we want to be able to read the priv_ptr field?

            return 1;
        }
    },
    {
        "set",
        [](lua_State* L)
        {
            auto& self = DAQHeaderIface.get(L, 1);
            luaL_checktype(L, 2, LUA_TTABLE);

            daq_header_set(L, 2, self);

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
            auto& self = DAQHeaderIface.get(L);
            lua_pushfstring(L, "%s@%p", DAQHeaderIface.name, &self);

            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            DAQHeaderIface.destroy(L);
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<_daq_pkthdr> DAQHeaderIface =
{
    "DAQHeader",
    methods,
    metamethods
};
