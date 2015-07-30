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
// pp_stream_splitter_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_stream_splitter_iface.h"

#include <limits>
#include <luajit-2.0/lua.hpp>

#include "lua/lua_arg.h"
#include "lua/lua_stack.h"
#include "stream/stream_splitter.h"
#include "pp_flow_iface.h"
#include "pp_raw_buffer_iface.h"

template<typename From, typename To>
static inline void stack_push(lua_State* L, const From v)
{ Lua::Stack<To>::push(L, static_cast<To>(v)); }

static const luaL_Reg methods[] =
{
    {
        "scan",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = StreamSplitterIface.get(L, 1);
            auto& flow = FlowIface.get(L, 2);
            auto& rb = RawBufferIface.get(L, 3);
            uint32_t len = arg.opt_size(4, rb.size(), rb.size());
            uint32_t flags = arg.opt_size(5);

            uint32_t fp = 0;
            auto status = self.scan(
                &flow, reinterpret_cast<const uint8_t*>(rb.data()),
                len, flags, &fp
            );

            stack_push<StreamSplitter::Status, unsigned>(L, status);
            Lua::Stack<uint32_t>::push(L, fp);

            return 2;
        }
    },
    {
        "reassemble",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& self = StreamSplitterIface.get(L, 1);
            auto& flow = FlowIface.get(L, 2);
            unsigned total = arg.check_size(3);
            unsigned offset = arg.check_size(4);
            auto& rb = RawBufferIface.get(L, 5);
            unsigned len = arg.opt_size(6, rb.size());
            uint32_t flags = arg.opt_size(7);

            unsigned copied = 0;

            auto sb = self.reassemble(
                &flow, total, offset,
                reinterpret_cast<const uint8_t*>(rb.data()), len,
                flags, copied
            );

            Lua::Stack<unsigned>::push(L, copied);

            if ( sb )
                RawBufferIface.create(
                    L, reinterpret_cast<const char*>(sb->data), sb->length);
            else
                lua_pushnil(L);

            return 2;
        }
    },
    {
        "finish",
        [](lua_State* L)
        {
            auto& self = StreamSplitterIface.get(L, 1);
            auto& flow = FlowIface.get(L, 2);

            bool result = self.finish(&flow);

            lua_pushboolean(L, result);

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
            auto& self = StreamSplitterIface.get(L);
            lua_pushfstring(L, "%s@%p", StreamSplitterIface.name, &self);

            return 1;
        }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            StreamSplitterIface.destroy(L);
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<StreamSplitter> StreamSplitterIface =
{
    "StreamSplitter",
    methods,
    metamethods
};
