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
// pp_flow_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_flow_iface.h"

#include "flow/flow.h"
#include "lua/lua_arg.h"

using namespace snort;

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            PktType type = static_cast<PktType>(args[1].opt_size());

            FlowIface.create(L).init(type);

            return 1;
        }
    },
    {
        "reset",
        [](lua_State* L)
        {
            FlowIface.get(L).reset();
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
            auto& self = FlowIface.get(L);
            lua_pushfstring(L, "%s@%p", FlowIface.name, &self);

            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            auto** t = FlowIface.regurgitate(L);
            (*t)->term();
            FlowIface.destroy(L, t);

            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<Flow> FlowIface =
{
    "Flow",
    methods,
    metamethods
};
