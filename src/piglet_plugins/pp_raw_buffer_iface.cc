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
// pp_raw_buffer_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_raw_buffer_iface.h"

#include "lua/lua_arg.h"

// FIXIT-H a lot of users keep references to this data.  Need to prevent
// Lua's garbage collection from destroying RawBuffer while other C++ types
// are using the data (unbeknownst to Lua).  Add a container data type
// which hold ref counts to RawBuffer and only frees when the ref count is
// zero.

static int init_from_string(lua_State* L)
{
    Lua::Args args(L);

    size_t len = 0;
    const char* s = args[1].check_string(len);
    size_t size = args[2].opt_size(len);

    // instantiate and adjust size if necessary
    RawBufferIface.create(L, s, len).resize(size, '\0');

    return 1;
}

static int init_from_size(lua_State* L)
{
    Lua::Args args(L);

    size_t size = args[1].opt_size();

    RawBufferIface.create(L, size, '\0');

    return 1;
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            if ( args[1].is_string() )
                return init_from_string(L);

            return init_from_size(L);
        }
    },
    {
        "size",
        [](lua_State* L)
        {
            auto& self = RawBufferIface.get(L);
            lua_pushinteger(L, self.size());
            return 1;
        }
    },
    {
        "resize",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = RawBufferIface.get(L, 1);
            size_t new_size = args[2].check_size();

            self.resize(new_size, '\0');

            return 0;
        }
    },
    {
        "write",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = RawBufferIface.get(L, 1);

            size_t len = 0;
            const char* s = args[2].check_string(len);
            size_t offset = args[3].opt_size();

            size_t required = offset + len;
            if ( self.size() < required )
                self.resize(required, '\0');

            self.replace(offset, len, s);

            return 0;
        }
    },
    {
        "read",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = RawBufferIface.get(L, 1);

            if ( args.count > 2 )
            {
                size_t start = args[2].check_size(self.size());
                size_t end = args[3].check_size(start, self.size());
                lua_pushlstring(L, self.data() + start, end - start);
            }
            else
            {
                size_t end = args[2].opt_size(self.size(), self.size());
                lua_pushlstring(L, self.data(), end);
            }

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
            auto& self = RawBufferIface.get(L);
            lua_pushlstring(L, self.data(), self.size());
            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        { return RawBufferIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<RawBuffer> RawBufferIface =
{
    "RawBuffer",
    methods,
    metamethods
};
