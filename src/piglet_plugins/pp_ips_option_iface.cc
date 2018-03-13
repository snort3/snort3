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
// pp_ips_option_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_ips_option_iface.h"

#include "framework/ips_option.h"
#include "lua/lua_stack.h"

#include "pp_packet_iface.h"
#include "pp_cursor_iface.h"

using namespace snort;

static const luaL_Reg methods[] =
{
    {
        "hash",
        [](lua_State* L)
        {
            uint32_t result = IpsOptionIface.get(L).hash();
            Lua::Stack<uint32_t>::push(L, result);
            return 1;
        }
    },
    {
        "is_relative",
        [](lua_State* L)
        {
            bool result = IpsOptionIface.get(L).is_relative();
            lua_pushboolean(L, result);
            return 1;
        }
    },
    {
        "fp_research",
        [](lua_State* L)
        {
            bool result = IpsOptionIface.get(L).fp_research();
            lua_pushboolean(L, result);
            return 1;
        }
    },
    {
        "get_cursor_type",
        [](lua_State* L)
        {
            CursorActionType cat = IpsOptionIface.get(L).get_cursor_type();
            Lua::Stack<unsigned>::push(L, static_cast<unsigned>(cat));
            return 1;
        }
    },
    {
        "eval",
        [](lua_State* L)
        {
            auto& c = CursorIface.get(L, 1);
            auto& p = PacketIface.get(L, 2);

            auto& self = IpsOptionIface.get(L);

            auto result = self.eval(c, &p);
            lua_pushinteger(L, result);

            return 1;
        }
    },
    {
        "action",
        [](lua_State* L)
        {
            auto& p = PacketIface.get(L);
            auto& self = IpsOptionIface.get(L);

            self.action(&p);

            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::InstanceInterface<IpsOption> IpsOptionIface =
{
    "IpsOption",
    methods
};
