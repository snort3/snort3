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
// pp_codec.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include <daq.h>
#include <luajit-2.0/lua.hpp>

#include "framework/module.h"
#include "framework/codec.h"
#include "helpers/lua.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "managers/codec_manager.h"
#include "managers/module_manager.h"
#include "piglet/piglet_api.h"

#include "piglet_plugin_common.h"

namespace CodecPiglet
{
using namespace Lua;
using namespace PigletCommon;

// -----------------------------------------------------------------------------
// Lua RawData Interface
// -----------------------------------------------------------------------------
namespace RawDataLib
{
using type = RawData;
const char* tname = "RawData";

static int raw_data_new(lua_State* L)
{
    auto rb = Interface::get_userdata<RawBufferLib::type>
            (L, RawBufferLib::tname, 1);

    auto t = Interface::create_userdata<type>(L, tname);

    // This must be freed by __gc!
    struct _daq_pkthdr* daq_hdr = cooked_daq_pkthdr(rb->size());
    *t = new type(daq_hdr, reinterpret_cast<uint8_t*>(rb->data()));
    (*t)->len = rb->size();

    return 1;
}

static int raw_data_destroy(lua_State* L)
{
    auto rd = Interface::get_userdata<type>(L, tname, 1);
    delete rd->pkth;
    delete rd;

    return 0;
}

static int raw_data_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static const luaL_reg methods[] =
{
    { "new", raw_data_new },
    { nullptr, nullptr }
};

static const luaL_reg metamethods[] =
{
    { "__gc", raw_data_destroy },
    { "__tostring", raw_data_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    methods,
    metamethods
};
} // namespace RawDataLib

// -----------------------------------------------------------------------------
// Lua CodecData Interface
// -----------------------------------------------------------------------------
namespace CodecDataLib
{
using type = CodecData;
const char* tname = "CodecData";

static int codec_data_new(lua_State* L)
{
    int init_prot = luaL_optinteger(L, 1, 0);
    auto t = Interface::create_userdata<type>(L, tname);
    *t = new type(init_prot);

    return 1;
}

static int codec_data_get_fields(lua_State* L)
{
    auto cd = Interface::get_userdata<type>(L, tname, 1);

    lua_newtable(L);
    int table = lua_gettop(L);

    lua_pushinteger(L, cd->next_prot_id);
    lua_setfield(L, table, "next_prot_id");

    lua_pushinteger(L, cd->lyr_len);
    lua_setfield(L, table, "lyr_len");

    lua_pushinteger(L, cd->invalid_bytes);
    lua_setfield(L, table, "invalid_bytes");

    lua_pushinteger(L, cd->proto_bits);
    lua_setfield(L, table, "proto_bits");

    lua_pushinteger(L, cd->codec_flags);
    lua_setfield(L, table, "codec_flags");

    lua_pushinteger(L, cd->ip_layer_cnt);
    lua_setfield(L, table, "ip_layer_cnt");

    lua_pushinteger(L, cd->ip6_extension_count);
    lua_setfield(L, table, "ip6_extension_count");

    lua_pushinteger(L, cd->curr_ip6_extension);
    lua_setfield(L, table, "curr_ip6_extension");

    lua_pushinteger(L, cd->ip6_csum_proto);
    lua_setfield(L, table, "ip6_csum_proto");

    return 1;
}

static int codec_data_set_fields(lua_State* L)
{
    auto cd = Interface::get_userdata<type>(L, tname, 1);

    int table = 2;
    luaL_checktype(L, table, LUA_TTABLE);

    lua_getfield(L, table, "next_prot_id");
    if ( lua_isnumber(L, -1) )
        cd->next_prot_id = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "lyr_len");
    if ( lua_isnumber(L, -1) )
        cd->lyr_len = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "invalid_bytes");
    if ( lua_isnumber(L, -1) )
        cd->invalid_bytes = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "proto_bits");
    if ( lua_isnumber(L, -1) )
        cd->proto_bits = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "codec_flags");
    if ( lua_isnumber(L, -1) )
        cd->codec_flags = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "ip_layer_cnt");
    if ( lua_isnumber(L, -1) )
        cd->ip_layer_cnt = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "ip6_extension_count");
    if ( lua_isnumber(L, -1) )
        cd->ip6_extension_count = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "curr_ip6_extension");
    if ( lua_isnumber(L, -1) )
        cd->curr_ip6_extension = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "ip6_csum_proto");
    if ( lua_isnumber(L, -1) )
        cd->ip6_csum_proto = lua_tointeger(L, -1);

    return 0;
}

static int codec_data_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static int codec_data_destroy(lua_State* L)
{
    delete Interface::get_userdata<type>(L, tname, 1);
    return 0;
}

static const luaL_reg methods[] =
{
    { "new", codec_data_new },
    { "get_fields", codec_data_get_fields },
    { "set_fields", codec_data_set_fields },
    { nullptr, nullptr }
};

static const luaL_reg metamethods[] =
{
    { "__gc", codec_data_destroy },
    { "__tostring", codec_data_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    methods,
    metamethods
};
} // namespace CodecDataLib

// -----------------------------------------------------------------------------
// Lua EncState Interface
// -----------------------------------------------------------------------------
namespace EncStateLib
{
using type = EncState;
const char* tname = "EncState";

static int enc_state_new(lua_State* L)
{
    unsigned long flags_hi = luaL_checkinteger(L, 1);
    unsigned long flags_lo = luaL_checkinteger(L, 2);
    uint8_t pr = luaL_checkinteger(L, 3);
    uint8_t ttl = luaL_checkinteger(L, 4);
    uint16_t data_size = luaL_checkinteger(L, 5);

    EncodeFlags flags = ((EncodeFlags)(flags_hi << 32)) | flags_lo;

    ip::IpApi* api = new ip::IpApi;
    auto t = Interface::create_userdata<type>(L, tname);

    *t = new type(*api, flags, pr, ttl, data_size);

    return 1;
}

static int enc_state_next_proto_set(lua_State* L)
{
    auto es = Interface::get_userdata<type>(L, tname, 1);
    lua_pushboolean(L, es->next_proto_set());

    return 1;
}

static int enc_state_ethertype_set(lua_State* L)
{
    auto es = Interface::get_userdata<type>(L, tname, 1);
    lua_pushboolean(L, es->ethertype_set());

    return 1;
}

static int enc_state_forward(lua_State* L)
{
    auto es = Interface::get_userdata<type>(L, tname, 1);
    lua_pushboolean(L, es->forward());

    return 1;
}

static int enc_state_get_ttl(lua_State* L)
{
    auto es = Interface::get_userdata<type>(L, tname, 1);
    uint8_t lyr_ttl = luaL_checkinteger(L, 2);
    lua_pushinteger(L, es->get_ttl(lyr_ttl));

    return 1;
}

static int enc_state_destroy(lua_State* L)
{
    auto es = Interface::get_userdata<type>(L, tname, 1);
    // hack to avoid having to store an extra reference to the ip::IpApi
    // that was alloc'd in enc_state_new()
    ip::IpApi* api = const_cast<ip::IpApi*>(&es->ip_api);
    delete api;
    delete es;

    return 0;
}

static int enc_state_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static const luaL_reg methods[] =
{
    { "new", enc_state_new },
    { "next_proto_set", enc_state_next_proto_set },
    { "ethertype_set", enc_state_ethertype_set },
    { "forward", enc_state_forward },
    { "get_ttl", enc_state_get_ttl },
    { nullptr, nullptr }
};

static const luaL_reg metamethods[] =
{
    { "__gc", enc_state_destroy },
    { "__tostring", enc_state_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    methods,
    metamethods
};
} // namespace EncStateLib

// -----------------------------------------------------------------------------
// Lua Buffer Interface
// -----------------------------------------------------------------------------
namespace BufferLib
{
using type = Buffer;
const char* tname = "Buffer";

static int buffer_new(lua_State* L)
{
    auto rb = Interface::get_userdata<RawBufferLib::type>
            (L, RawBufferLib::tname, 1);

    size_t size = opt_size_param(L, 2, rb->size(), rb->size());

    auto t = Interface::create_userdata<type>(L, tname);
    *t = new type(reinterpret_cast<uint8_t*>(rb->data()), size);

    return 1;
}

static int buffer_destroy(lua_State* L)
{
    auto b = Interface::get_userdata<type>(L, tname, 1);
    delete b;

    return 0;
}

static int buffer_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static const luaL_reg methods[] =
{
    { "new", buffer_new },
    { nullptr, nullptr }
};

static const luaL_reg metamethods[] =
{
    { "__gc", buffer_destroy },
    { "__tostring", buffer_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    methods,
    metamethods
};
} // namespace BufferLib

// -----------------------------------------------------------------------------
// Lua Interface for Codec instance
// -----------------------------------------------------------------------------
namespace Instance
{
struct TextLogWrapper
{
    TextLog* text_log;

    TextLogWrapper(const char* name)
    { text_log = TextLog_Init(name); }

    ~TextLogWrapper()
    { TextLog_Term(text_log); }
};

template<typename T>
static int fill_table_from_vector(lua_State* L, std::vector<T>& v)
{
    luaL_checkstack(L, v.size() + 3, "can't allocate stack space");
    lua_newtable(L);

    int table = lua_gettop(L);

    for ( size_t i = 0; i < v.size(); i++ )
    {
        lua_pushnumber(L, v[i]);
        lua_rawseti(L, table, i + 1);
    }

    return 1;
}

int instance_get_name(lua_State* L)
{
    auto i = Util::regurgitate_instance<Codec>(L, 1);

    lua_pushstring(L, i->get_name());

    return 1;
}

int instance_get_data_link_type(lua_State* L)
{
    std::vector<int> types;
    auto i = Util::regurgitate_instance<Codec>(L, 1);

    i->get_data_link_type(types);

    return fill_table_from_vector(L, types);
}

int instance_get_protocol_ids(lua_State* L)
{
    std::vector<uint16_t> ids;
    auto i = Util::regurgitate_instance<Codec>(L, 1);

    i->get_protocol_ids(ids);

    return fill_table_from_vector(L, ids);
}

int instance_decode(lua_State* L)
{
    auto i = Util::regurgitate_instance<Codec>(L, 1);

    auto rd = Interface::get_userdata<RawDataLib::type>
            (L, RawDataLib::tname, 1);

    auto cd = Interface::get_userdata<CodecDataLib::type>
            (L, CodecDataLib::tname, 2);

    auto dd = Interface::get_userdata<DecodeDataLib::type>
            (L, DecodeDataLib::tname, 3);

    bool b = i->decode(*rd, *cd, *dd);
    lua_pushboolean(L, b);

    return 1;
}

int instance_log(lua_State* L)
{
    TextLogWrapper tl("stdout");

    auto i = Util::regurgitate_instance<Codec>(L, 1);
    auto rb = Interface::get_userdata<RawBufferLib::type>
            (L, RawBufferLib::tname, 1);

    int lyr_len = luaL_checkinteger(L, 2);

    i->log(tl.text_log, reinterpret_cast<uint8_t*>(rb->data()), lyr_len);

    return 0;
}

int instance_encode(lua_State* L)
{
    auto i = Util::regurgitate_instance<Codec>(L, 1);
    auto rb = Interface::get_userdata<RawBufferLib::type>
            (L, RawBufferLib::tname, 1);

    int raw_len = luaL_checkinteger(L, 2);
    auto es = Interface::get_userdata<EncStateLib::type>
            (L, EncStateLib::tname, 3);

    auto buffer = Interface::get_userdata<BufferLib::type>
            (L, BufferLib::tname, 4);

    bool b = i->encode(
        reinterpret_cast<uint8_t*>(rb->data()),
        raw_len, *es, *buffer
        );

    lua_pushboolean(L, b);

    return 1;
}

int instance_update(lua_State* L)
{
    ip::IpApi api;

    auto i = Util::regurgitate_instance<Codec>(L, 1);
    unsigned long flags_hi = luaL_checkinteger(L, 1);
    unsigned long flags_lo = luaL_checkinteger(L, 2);
    auto rb = Interface::get_userdata<RawBufferLib::type>
            (L, RawBufferLib::tname, 3);

    lua_Integer lyr_len = luaL_checkinteger(L, 4);
    uint32_t updated_len = 0;

    EncodeFlags flags = ((EncodeFlags)flags_hi << 32) | flags_lo;

    i->update(
        api, flags,
        reinterpret_cast<uint8_t*>(rb->data()),
        lyr_len,
        updated_len
        );

    lua_pushinteger(L, updated_len);

    return 1;
}

int instance_format(lua_State* L)
{
    auto i = Util::regurgitate_instance<Codec>(L, 1);
    bool reverse = lua_toboolean(L, 1);
    auto rb = Interface::get_userdata<RawBufferLib::type>
            (L, RawBufferLib::tname, 2);

    auto dd = Interface::get_userdata<DecodeDataLib::type>
            (L, DecodeDataLib::tname, 3);

    i->format(reverse, reinterpret_cast<uint8_t*>(rb->data()), *dd);

    return 0;
}

static const luaL_reg methods[] =
{
    { "get_name", instance_get_name },
    { "get_data_link_type", instance_get_data_link_type },
    { "get_protocol_ids", instance_get_protocol_ids },
    { "decode", instance_decode },
    { "log", instance_log },
    { "encode", instance_encode },
    { "update", instance_update },
    { "format", instance_format },
    { nullptr, nullptr }
};
} // namespace Instance

// -----------------------------------------------------------------------------
// Plugin foo
// -----------------------------------------------------------------------------

class Plugin : public Piglet::BasePlugin
{
public:
    Plugin(Lua::State&, std::string);
    virtual ~Plugin() override;
    virtual bool setup() override;

private:
    CodecWrapper* wrapper;
};

Plugin::Plugin(Lua::State& state, std::string target) :
    BasePlugin(state, target)
{
    auto m = ModuleManager::get_default_module(target.c_str(), snort_conf);
    if ( m )
        wrapper = CodecManager::instantiate(target.c_str(), m, snort_conf);
}

Plugin::~Plugin()
{
    if ( wrapper )
        delete wrapper;
}

bool Plugin::setup()
{
    // FIXIT-M: Need better error reporting
    if ( !wrapper )
        return true;

    Interface::register_lib(L, &RawBufferLib::lib);
    Interface::register_lib(L, &RawDataLib::lib);
    Interface::register_lib(L, &CodecDataLib::lib);
    Interface::register_lib(L, &DecodeDataLib::lib);
    Interface::register_lib(L, &EncStateLib::lib);
    Interface::register_lib(L, &BufferLib::lib);

    Util::register_instance_lib(
        L, Instance::methods, "Codec", wrapper->instance
        );

    return false;
}
}  // namespace CodecPiglet

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------

static Piglet::BasePlugin* ctor(Lua::State& state, std::string target, Module*)
{ return new CodecPiglet::Plugin(state, target); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api codec_piglet_api =
{
    {
        PT_PIGLET,
        Piglet::API_SIZE,
        Piglet::API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_codec",
        Piglet::API_HELP,
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_CODEC
};

#ifdef BUILDING_SO

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &codec_piglet_api.base,
    nullptr
};

#else

const BaseApi* pp_codec = &codec_piglet_api.base;

#endif

