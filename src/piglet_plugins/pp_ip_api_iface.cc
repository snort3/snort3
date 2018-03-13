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
// pp_ip_api_iface.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pp_ip_api_iface.h"

#include "lua/lua_arg.h"
#include "protocols/ip.h"

#include "pp_raw_buffer_iface.h"

using namespace snort;

template<typename Header>
static void set_header(lua_State* L, ip::IpApi& ip_api, RawBuffer& rb)
{
    if ( rb.size() < sizeof(Header) )
        luaL_error(L,
            "buffer is to small to be cast to header, (need %d, got %d)",
            sizeof(Header), rb.size()
        );

    else
    {
        const auto* hdr = reinterpret_cast<const Header*>(rb.data());
        ip_api.set(hdr);
    }
}

template<typename Header>
static int set(lua_State* L)
{
    Lua::Args args(L);
    auto & self = IpApiIface.get(L, 1);

    RawBuffer* rb;
    int ref_index = 2;

    if ( RawBufferIface.is(L, 2) )
        rb = &RawBufferIface.get(L, 2);

    else
    {
        size_t len = 0;
        const char* data = args[2].check_string(len);
        rb = &RawBufferIface.create(L, data, len);
        ref_index = lua_gettop(L);
    }

    set_header<Header>(L, self, *rb);

    Lua::add_ref(L, &self, "iph", ref_index);

    return 0;
}

static const luaL_Reg methods[] =
{
    {
        "set_ip4",
        [](lua_State* L)
        { return set<ip::IP4Hdr>(L); }
    },
    {
        "set_ip6",
        [](lua_State* L)
        { return set<ip::IP6Hdr>(L); }
    },
    {
        "reset",
        [](lua_State* L)
        { IpApiIface.get(L).reset(); return 0; }
    },
    { nullptr, nullptr }
};

static const luaL_Reg metamethods[] =
{
    {
        "__tostring",
        [](lua_State* L)
        { return IpApiIface.default_tostring(L); }
    },
    {
        "__gc",
        [](lua_State* L)
        {
            // don't need to delete, because this object is a pointer to
            // a member of a DecodeData
            Lua::remove_refs(L, static_cast<void*>(&IpApiIface.get(L)));
            return 0;
        }
    },
    { nullptr, nullptr }
};

const struct Lua::TypeInterface<ip::IpApi> IpApiIface =
{
    "IpApi",
    methods,
    metamethods
};
