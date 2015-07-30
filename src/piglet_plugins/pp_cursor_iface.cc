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
// pp_cursor_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_cursor_iface.h"

#include <luajit-2.0/lua.hpp>

#include "framework/cursor.h"
#include "pp_packet_iface.h"

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            auto& p = PacketIface.get(L);
            CursorIface.create(L, &p);

            return 1;
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
            auto& self = CursorIface.get(L);
            lua_pushfstring(L, "%s@%p", CursorIface.name, &self);

            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            CursorIface.destroy(L);
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<Cursor> CursorIface =
{
    "Cursor",
    methods,
    metamethods
};
