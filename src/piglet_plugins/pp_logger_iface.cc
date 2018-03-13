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
// pp_logger_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_logger_iface.h"

#include "framework/logger.h"
#include "lua/lua_arg.h"

#include "pp_event_iface.h"
#include "pp_packet_iface.h"

using namespace snort;

static const luaL_Reg methods[] =
{
    {
        "open",
        [](lua_State* L)
        {
            LoggerIface.get(L).open();
            return 0;
        }
    },
    {
        "close",
        [](lua_State* L)
        {
            LoggerIface.get(L).close();
            return 0;
        }
    },
    {
        "reset",
        [](lua_State* L)
        {
            LoggerIface.get(L).reset();
            return 0;
        }
    },
    {
        "alert",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& p = PacketIface.get(L, 1);
            auto& e = EventIface.get(L, 3);

            auto& self = LoggerIface.get(L);

            const char* msg = args[2].check_string();
            self.alert(&p, msg, e);

            return 0;
        }
    },
    {
        "log",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& p = PacketIface.get(L, 1);
            auto& e = EventIface.get(L, 3);

            auto& self = LoggerIface.get(L);

            const char* msg = args[2].check_string();
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
