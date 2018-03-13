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
// pp_stream_splitter_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_stream_splitter_iface.h"

#include "lua/lua_arg.h"
#include "stream/stream_splitter.h"

#include "pp_flow_iface.h"
#include "pp_raw_buffer_iface.h"

using namespace snort;

template<typename From, typename To>
static inline void stack_push(lua_State* L, const From v)
{ Lua::Stack<To>::push(L, static_cast<To>(v)); }

static const luaL_Reg methods[] =
{
    {
        "scan",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = StreamSplitterIface.get(L, 1);
            auto& flow = FlowIface.get(L, 2);
            auto& rb = RawBufferIface.get(L, 3);
            uint32_t len = args[4].opt_size(rb.size(), rb.size());
            uint32_t flags = args[5].opt_size();

            uint32_t fp = 0;
            auto status = self.scan(&flow, get_data(rb), len, flags, &fp);

            stack_push<StreamSplitter::Status, unsigned>(L, status);
            Lua::Stack<uint32_t>::push(L, fp);

            return 2;
        }
    },
    {
        "reassemble",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& self = StreamSplitterIface.get(L, 1);
            auto& flow = FlowIface.get(L, 2);
            unsigned total = args[3].check_size();
            unsigned offset = args[4].check_size();
            auto& rb = RawBufferIface.get(L, 5);
            unsigned len = args[6].opt_size(rb.size());
            uint32_t flags = args[7].opt_size();

            unsigned copied = 0;

            auto sb = self.reassemble(&flow, total, offset, get_data(rb), len,
                flags, copied);

            Lua::Stack<unsigned>::push(L, copied);

            if ( sb.data )
                RawBufferIface.create(
                    L, reinterpret_cast<const char*>(sb.data), sb.length);
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
        { return StreamSplitterIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        { return StreamSplitterIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<StreamSplitter> StreamSplitterIface =
{
    "StreamSplitter",
    methods,
    metamethods
};
