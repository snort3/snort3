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
// pp_cursor_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_cursor_iface.h"

#include "framework/cursor.h"
#include "lua/lua_arg.h"
#include "protocols/packet.h"

#include "pp_packet_iface.h"
#include "pp_raw_buffer_iface.h"

using namespace snort;

static void reset_from_packet(
    lua_State* L, Cursor& self, Packet& p, int p_idx)
{
    self.reset(&p);
    Lua::add_ref(L, &self, "data", p_idx);
}

static void reset_from_raw_buffer(
    lua_State* L, Cursor& self, RawBuffer& rb, int rb_idx)
{
    Packet p;
    p.reset();

    p.data = get_data(rb);
    p.dsize = rb.size();

    self.reset(&p);
    Lua::add_ref(L, &self, "data", rb_idx);
}

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);
            Packet p;
            p.reset();

            auto& self = CursorIface.create(L, &p);

            if ( args.count )
            {
                if ( PacketIface.is(L, 1) )
                {
                    reset_from_packet(L, self, PacketIface.get(L, 1), 1);
                }
                else if ( args[1].is_string() )
                {
                    size_t len = 0;
                    const char* s = args[1].check_string(len);
                    auto& rb = RawBufferIface.create(L, s, len);
                    reset_from_raw_buffer(L, self, rb, lua_gettop(L));
                    lua_pop(L, 1);
                }
                else
                {
                    reset_from_raw_buffer(L, self, RawBufferIface.get(L, 1), 1);
                }
            }

            return 1;
        }
    },
    {
        "reset",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = CursorIface.get(L, 1);

            if ( args.count > 1 )
            {
                if ( PacketIface.is(L, 2) )
                {
                    auto& p = PacketIface.get(L, 2);
                    reset_from_packet(L, self, p, 2);
                }
                else
                {
                    if ( args[2].is_string() )
                    {
                        size_t len = 0;
                        const char* s = args[2].check_string(len);
                        auto& rb = RawBufferIface.create(L, s, len);
                        reset_from_raw_buffer(L, self, rb, lua_gettop(L));
                    }
                    else
                    {
                        auto& rb = RawBufferIface.get(L, 2);
                        reset_from_raw_buffer(L, self, rb, 2);
                    }
                }
            }
            else
            {
                Packet p;

                p.reset();
                self.reset(&p);

                Lua::remove_ref(L, &self, "data");
            }

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
        { return CursorIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        { return CursorIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<Cursor> CursorIface =
{
    "Cursor",
    methods,
    metamethods
};
