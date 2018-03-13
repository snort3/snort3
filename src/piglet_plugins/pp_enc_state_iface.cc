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
// pp_enc_state_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_enc_state_iface.h"

#include "framework/codec.h"
#include "lua/lua_arg.h"

using namespace snort;

// FIXIT-M ip_api should also be its own object (copyable)
static const class ip::IpApi ip_api {};

static inline uint64_t get_encode_flag(uint32_t hi, uint32_t lo)
{ return (static_cast<uint64_t>(hi) << 4) | lo; }

static const luaL_Reg methods[] =
{
    {
        "new",
        [](lua_State* L)
        {
            Lua::Args args(L);

            uint32_t efl_hi = args[1].opt_size();
            uint32_t efl_lo = args[2].opt_size();
            IpProtocol next_proto = (IpProtocol)args[3].opt_size();
            uint8_t ttl = args[4].opt_size();
            uint16_t dsize = args[5].opt_int();

            EncStateIface.create(L, ip_api, get_encode_flag(efl_hi, efl_lo),
                    next_proto, ttl, dsize);

            return 1;
        }
    },
    // FIXIT-L add get and set methods
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        { return EncStateIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        { return EncStateIface.default_gc(L); }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<EncState> EncStateIface =
{
    "EncState",
    methods,
    metamethods
};
