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
// pp_buffer_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_buffer_iface.h"

#include "framework/codec.h"
#include "lua/lua_arg.h"

#include "pp_raw_buffer_iface.h"

using namespace snort;

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            RawBuffer* rb;
            size_t len;
            int idx = 1;

            if ( args[1].is_string() )
            {
                // Create a RawBuffer object to back the string
                len = 0;
                const char* s = args[1].check_string(len);
                rb = &RawBufferIface.create(L, s, len);
                idx = lua_gettop(L);
            }
            else if ( args[1].is_size() )
            {
                len = args[1].check_size();
                // Create a RawBuffer object to back the string
                rb = &RawBufferIface.create(L, len, '\0');
                idx = lua_gettop(L);
            }
            else
            {
                rb = &RawBufferIface.get(L, 1);
            }

            auto& self = BufferIface.create(L, get_mutable_data(*rb), rb->size());
            // Save a reference to the RawBuffer
            // FIXIT-M integrate add_ref() into the interface code so we don't
            // have to do this explicitly
            Lua::add_ref(L, &self, "data", idx);

            return 1;
        }
    },
    {
        "allocate",
        [](lua_State* L)
        {
            Lua::Args args(L);
            auto& self = BufferIface.get(L, 1);
            uint32_t len = args[2].check_size();
            bool result = self.allocate(len);
            lua_pushboolean(L, result);
            return 1;
        }
    },
    {
        "clear",
        [](lua_State* L)
        {
            BufferIface.get(L).clear();
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
            auto& self = BufferIface.get(L);
            lua_pushlstring(L, reinterpret_cast<const char*>(self.data()),
                self.size());
            // lua_pushfstring(L, "%s@%p", BufferIface.name, &self);

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
