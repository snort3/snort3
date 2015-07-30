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
// pp_logger_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_logger_iface.h"

#include <luajit-2.0/lua.hpp>

#include "framework/logger.h"
#include "lua/lua_arg.h"
#include "lua/lua_stack.h"
#include "pp_event_iface.h"
#include "pp_packet_iface.h"

static const luaL_Reg methods[] =
{
    {
        "open",
        [](lua_State* L)
        {
            auto& self = LoggerIface.get(L);
            self.open();
            return 0;
        }
    },
    {
        "close",
        [](lua_State* L)
        {
            auto& self = LoggerIface.get(L);
            self.close();
            return 0;
        }
    },
    {
        "reset",
        [](lua_State* L)
        {
            auto& self = LoggerIface.get(L);
            self.reset();
            return 0;
        }
    },
    {
        "alert",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& p = PacketIface.get(L, 1);
            const char* msg = arg.check_string(2);
            auto& e = EventIface.get(L, 3);

            auto& self = LoggerIface.get(L);

            self.alert(&p, msg, &e);

            return 0;
        }
    },
    {
        "log",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& p = PacketIface.get(L, 1);
            const char* msg = arg.check_string(2);
            auto& e = EventIface.get(L, 3);

            auto& self = LoggerIface.get(L);

            self.log(&p, msg, &e);

            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::InstanceInterface<Logger> LoggerIface =
{
    "Logger",
    methods
};
