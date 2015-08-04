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
// pp_inspector_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_inspector_iface.h"

#include <limits>
#include <string>
#include <assert.h>
#include <luajit-2.0/lua.hpp>

#include "framework/inspector.h"
#include "lua/lua_arg.h"
#include "pp_packet_iface.h"
#include "pp_raw_buffer_iface.h"
#include "pp_stream_splitter_iface.h"

template<typename T>
static inline bool get_buf(
    Inspector& i, T v, Packet& p, std::string& rb)
{
    struct InspectionBuffer ib;
    bool result = i.get_buf(v, &p, ib);

    if ( result )
        rb.assign(reinterpret_cast<const char*>(ib.data), ib.len);

    return result;
}

static const luaL_Reg methods[] =
{
    {
        "eval",
        [](lua_State* L)
        {
            auto& p = PacketIface.get(L);
            auto& self = InspectorIface.get(L);

            self.eval(&p);

            return 0;
        }
    },
    {
        "clear",
        [](lua_State* L)
        {
            auto& p = PacketIface.get(L);
            auto& self = InspectorIface.get(L);
            
            self.clear(&p);

            return 0;
        }
    },
    {
        "get_buf_from_key",
        [](lua_State* L)
        {
            bool result;

            auto& p = PacketIface.get(L, 2);
            auto& rb = RawBufferIface.get(L, 3);
            auto& self = InspectorIface.get(L);

            {
                auto key = Lua::Stack<std::string>::get(L, 1);
                result = get_buf(self, key.c_str(), p, rb);
            }

            lua_pushboolean(L, result);

            return 1;
        }
    },
    {
        "get_buf_from_id",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            int id = arg.check_int(1);
            auto& p = PacketIface.get(L, 2);
            auto& rb = RawBufferIface.get(L, 3);

            auto& self = InspectorIface.get(L);

            bool result = get_buf(self, id, p, rb);

            lua_pushboolean(L, result);

            return 1;
        }
    },
    {
        "get_buf_from_type",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            int type = arg.check_int(1);
            auto& p = PacketIface.get(L, 2);
            auto& rb = RawBufferIface.get(L, 3);

            auto& self = InspectorIface.get(L);

            bool result = get_buf(
                self,
                static_cast<InspectionBuffer::Type>(type),
                p, rb
            );

            lua_pushboolean(L, result);

            return 1;
        }
    },
    {
        "get_splitter",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            bool to_server = arg.check_boolean(1);
            auto& self = InspectorIface.get(L);

            auto** sp = StreamSplitterIface.allocate(L);
            *sp = self.get_splitter(to_server);

            if ( *sp == nullptr )
                lua_pushnil(L);

            return 1;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::InstanceInterface<Inspector> InspectorIface =
{
    "Inspector",
    methods
};
