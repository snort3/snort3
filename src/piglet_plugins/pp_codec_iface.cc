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
// pp_codec_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_codec_iface.h"

#include "framework/codec.h"
#include "lua/lua_arg.h"
#include "log/text_log.h"

#include "pp_buffer_iface.h"
#include "pp_codec_data_iface.h"
#include "pp_daq_pkthdr_iface.h"
#include "pp_decode_data_iface.h"
#include "pp_enc_state_iface.h"
#include "pp_flow_iface.h"
#include "pp_ip_api_iface.h"
#include "pp_raw_buffer_iface.h"

using namespace snort;

// FIXIT-M delete this, and make the IpApi arg in codec.update required
static const ip::IpApi default_ip_api {};

struct TextLogWrapper
{
    TextLog* text_log;

    TextLogWrapper(const char* name)
    {
        text_log = TextLog_Init(name);
        assert(text_log);
    }

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

            std::vector<ProtocolId> ret;
            self.get_protocol_ids(ret);

            //  Convert ProtocolId vector to uint16_t vector to make
            //  Lua templates happy.
            //  FIXIT-L  add support for ProtocolId in Lua code.
            std::vector<uint16_t> tmp;
            tmp.reserve(ret.size());
            for(auto a: ret)
                tmp.push_back(to_utype(a));

            lua_newtable(L);
            Lua::fill_table_from_vector(L, lua_gettop(L), tmp);

            return 1;
        }
    },
    {
        "decode",
        [](lua_State* L)
        {
            bool result;

            auto& daq = DAQHeaderIface.get(L, 1);
            auto& cd = CodecDataIface.get(L, 3);
            auto& dd = DecodeDataIface.get(L, 4);

            auto& self = CodecIface.get(L);

            if ( RawBufferIface.is(L, 2) )
            {
                RawData rd(&daq, get_data(RawBufferIface.get(L, 2)));
                result = self.decode(rd, cd, dd);
            }
            else
            {
                size_t len = 0;
                RawData rd(
                    &daq,
                    reinterpret_cast<const uint8_t*>(
                        luaL_checklstring(L, 2, &len)
                    )
                );

                result = self.decode(rd, cd, dd);
            }

            lua_pushboolean(L, result);

            return 1;
        }
    },
    {
        "log",
        [](lua_State* L)
        {
            Lua::Args args(L);

            auto& rb = RawBufferIface.get(L, 1);
            uint16_t lyr_len = args[2].opt_size(rb.size(), rb.size());

            auto& self = CodecIface.get(L);

            TextLogWrapper tl_wrap("stdout");
            self.log(tl_wrap.text_log, get_data(rb), lyr_len);

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
            auto& flow = FlowIface.get(L, 4);

            auto& self = CodecIface.get(L);

            bool result = self.encode(get_data(rb), rb.size(), es, b, &flow);

            lua_pushboolean(L, result);

            return 1;
        }
    },
    {
        "update",
        [](lua_State* L)
        {
            Lua::Args args(L);

            // FIXIT-M this hacky arg offset stuff is for backwards compatibility
            // it will be removed in later updates

            int off = 0;
            const auto* ip_api = &default_ip_api;

            if ( IpApiIface.is(L, 1) )
            {
                ip_api = &IpApiIface.get(L, 1);
                off++;
            }

            uint32_t flags_hi = args[off + 1].check_size();
            uint32_t flags_lo = args[off + 2].check_size();
            auto& rb = RawBufferIface.get(L, off + 3);

            // FIXIT-L Args vs Iface is not orthogonal
            uint16_t lyr_len = args[off + 4].opt_size(0, rb.size());

            auto& self = CodecIface.get(L);

            uint32_t updated_len = 0;

            uint64_t flags = (static_cast<uint64_t>(flags_hi) << 8) | flags_lo;

            self.update(*ip_api, flags, get_mutable_data(rb), lyr_len,
                updated_len);

            lua_pushinteger(L, updated_len);

            return 1;
        }
    },
    {
        "format",
        [](lua_State* L)
        {
            Lua::Args args(L);

            bool reverse = args[1].get_bool();
            auto& rb = RawBufferIface.get(L, 2);
            auto& dd = DecodeDataIface.get(L, 3);

            auto& self = CodecIface.get(L);

            self.format(reverse, get_mutable_data(rb), dd);

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
