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
// pp_codec_iface.cc author Joel Cornett <jocornet@cisco.com>

#include "pp_codec_iface.h"

#include <limits>
#include <vector>
#include <luajit-2.0/lua.hpp>

#include "framework/codec.h"
#include "lua/lua_arg.h"
#include "lua/lua_table.h"
#include "protocols/ip.h"
#include "log/text_log.h"

#include "pp_buffer_iface.h"
#include "pp_codec_data_iface.h"
#include "pp_decode_data_iface.h"
#include "pp_enc_state_iface.h"
#include "pp_raw_buffer_iface.h"
#include "pp_raw_data_iface.h"

static std::vector<int> data_link_types;
static std::vector<uint16_t> protocol_ids;

static const ip::IpApi ip_api {};
 
struct TextLogWrapper
{
    TextLog* text_log;

    TextLogWrapper(const char* name)
    { text_log = TextLog_Init(name); }

    ~TextLogWrapper()
    {
        if ( text_log )
            TextLog_Term(text_log);
    }
};

static const luaL_Reg methods[] =
{
    {
        "get_data_link_type",
        [](lua_State* L)
        {
            auto& self = CodecIface.get(L);

            std::vector<int> ret;
            self.get_data_link_type(ret);

            lua_newtable(L);
            Lua::fill_table_from_vector(L, lua_gettop(L), ret);

            return 1;
        }
    },
    {
        "get_protocol_ids",
        [](lua_State* L)
        {
            auto& self = CodecIface.get(L);

            std::vector<uint16_t> ret;
            self.get_protocol_ids(ret);

            lua_newtable(L);
            Lua::fill_table_from_vector(L, lua_gettop(L), ret);

            return 1;
        }
    },
    {
        "decode",
        [](lua_State* L)
        {
            auto& rd = RawDataIface.get(L, 1);
            auto& cd = CodecDataIface.get(L, 2);
            auto& dd = DecodeDataIface.get(L, 3);

            auto& self = CodecIface.get(L);

            bool result = self.decode(rd, cd, dd);
            lua_pushboolean(L, result);

            return 1;
        }
    },
    {
        "log",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            auto& rb = RawBufferIface.get(L, 1);
            uint16_t lyr_len = arg.opt_size(2, rb.size(), rb.size());

            auto& self = CodecIface.get(L);

            TextLogWrapper tl_wrap("stdout");
            // FIXIT-L: Do we need to check for null tl_wrap.text_log?
            self.log(
                tl_wrap.text_log,
                reinterpret_cast<const uint8_t*>(rb.data()),
                lyr_len
            );

            return 0;
        }
    },
    {
        "encode",
        [](lua_State* L)
        {
            auto& rb = RawBufferIface.get(L, 1); // raw_in
            auto& es = EncStateIface.get(L, 2);
            auto& b = BufferIface.get(L, 3);

            auto& self = CodecIface.get(L);

            bool result = self.encode(
                reinterpret_cast<const uint8_t*>(rb.data()), rb.size(), es, b);

            lua_pushboolean(L, result);

            return 1;
        }
    },
    {
        "update",
        [](lua_State* L)
        {
            Lua::Arg arg(L);

            // FIXIT-M: We can't represent all flags int lua_Integer type
            uint64_t flags = arg.check_size(1);
            auto& rb = RawBufferIface.get(L, 2);
            uint16_t lyr_len = arg.opt_size(3, 0, rb.size());

            auto& self = CodecIface.get(L);

            uint32_t updated_len = 0;

            self.update(
                ip_api, flags,
                const_cast<uint8_t*>(
                    reinterpret_cast<const uint8_t*>(rb.data())),
                lyr_len, updated_len
            );

            lua_pushinteger(L, updated_len);

            return 1;
        }
    },
    {
        "format",
        [](lua_State* L)
        {
            bool reverse = lua_toboolean(L, 1);
            auto& rb = RawBufferIface.get(L, 2);
            auto& dd = DecodeDataIface.get(L, 3);

            auto& self = CodecIface.get(L);
            self.format(
                reverse,
                const_cast<uint8_t*>(
                    reinterpret_cast<const uint8_t*>(rb.data())),
                dd
            );

            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::InstanceInterface<Codec> CodecIface =
{
    "Codec",
    methods
};
