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
// pp_buffer_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_buffer_iface.h"

#include <luajit-2.0/lua.hpp>

#include "framework/codec.h"
#include "pp_raw_buffer_iface.h"

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            // FIXIT-M: need a way to track refs to other
            //          objs in lua so the don't get gc'd too early
            auto& rb = RawBufferIface.get(L);
            BufferIface.create(
                L,
                const_cast<uint8_t*>(
                    reinterpret_cast<const uint8_t*>(rb.data())),
                rb.size()
            );

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
            auto& self = BufferIface.get(L);
            lua_pushfstring(L, "%s@%p", BufferIface.name, &self);

            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            BufferIface.destroy(L);
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<Buffer> BufferIface =
{
    "Buffer",
    methods,
    metamethods
};
