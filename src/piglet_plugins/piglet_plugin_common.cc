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
// piglet_plugin_common.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugin_common.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/signature.h"
#include "events/event.h"

namespace PigletCommon
{
//-------------------------------------------------------------------------
// Lua Raw Buffer Interface
//-------------------------------------------------------------------------

namespace RawBufferLib
{
const char* tname = "RawBuffer";

static int raw_buffer_new(lua_State* L)
{
    auto t = Interface::create_userdata<type>(L, tname);
    size_t size = check_size_param(L, 1);

    *t = new type(size);

    return 1;
}

static int raw_buffer_length(lua_State* L)
{
    auto rb = Interface::get_userdata<type>(L, tname, 1);
    lua_pushnumber(L, rb->size());

    return 1;
}

static int raw_buffer_write(lua_State* L)
{
    auto rb = Interface::get_userdata<type>(L, tname, 1);
    size_t offset = check_size_param(L, 2, rb->size());

    size_t length;
    const char* s = luaL_checklstring(L, 3, &length);

    if ( length + offset > rb->size() )
        length = rb->size() - offset;

    memcpy(&rb->data()[offset], s, length);

    return 0;
}

static int raw_buffer_read(lua_State* L)
{
    auto rb = Interface::get_userdata<type>(L, tname, 1);
    size_t offset = check_size_param(L, 2, rb->size());
    size_t length = check_size_param(L, 3, rb->size() - offset);

    lua_pushlstring(L, &rb->data()[offset], length);

    return 1;
}

static int raw_buffer_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static int raw_buffer_destroy(lua_State* L)
{
    delete Interface::get_userdata<type>(L, tname, 1);
    return 0;
}

static const luaL_reg raw_buffer_methods[] =
{
    { "new", raw_buffer_new },
    { "length", raw_buffer_length },
    { "write", raw_buffer_write },
    { "read", raw_buffer_read },
    { nullptr, nullptr }
};

static const luaL_reg raw_buffer_metamethods[] =
{
    { "__gc", raw_buffer_destroy },
    { "__tostring", raw_buffer_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    raw_buffer_methods,
    raw_buffer_metamethods
};
} // namespace RawBufferLib

// -----------------------------------------------------------------------------
// Lua DecodeData Interface
// -----------------------------------------------------------------------------
namespace DecodeDataLib
{
const char* tname = "DecodeData";

static int decode_data_new(lua_State* L)
{
    auto t = Interface::create_userdata<type>(L, tname);
    *t = new type();
    (*t)->reset();

    return 1;
}

static int decode_data_get_fields(lua_State* L)
{
    auto dd = Interface::get_userdata<type>(L, tname, 1);

    lua_newtable(L);
    int table = lua_gettop(L);

    lua_pushinteger(L, dd->sp);
    lua_setfield(L, table, "sp");

    lua_pushinteger(L, dd->dp);
    lua_setfield(L, table, "dp");

    lua_pushinteger(L, dd->decode_flags);
    lua_setfield(L, table, "decode_flags");

    lua_pushinteger(L, static_cast<lua_Integer>(dd->type));
    lua_setfield(L, table, "pkt_type");

    return 1;
}

static int decode_data_set_fields(lua_State* L)
{
    auto dd = Interface::get_userdata<type>(L, tname, 1);

    luaL_checktype(L, 2, LUA_TTABLE);
    int table = lua_gettop(L);

    lua_getfield(L, table, "sp");
    if ( lua_isnumber(L, -1) )
        dd->sp = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "dp");
    if ( lua_isnumber(L, -1) )
        dd->dp = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "decode_flags");
    if ( lua_isnumber(L, -1) )
        dd->decode_flags = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "pkt_type");
    if ( lua_isnumber(L, -1) )
        dd->type = static_cast<PktType>(lua_tointeger(L, -1));

    return 0;
}

static int decode_data_get_mplshdr_fields(lua_State* L)
{
    auto dd = Interface::get_userdata<type>(L, tname, 1);

    lua_newtable(L);
    int table = lua_gettop(L);

    lua_pushinteger(L, dd->mplsHdr.label);
    lua_setfield(L, table, "label");

    lua_pushinteger(L, dd->mplsHdr.exp);
    lua_setfield(L, table, "exp");

    lua_pushinteger(L, dd->mplsHdr.bos);
    lua_setfield(L, table, "bos");

    lua_pushinteger(L, dd->mplsHdr.ttl);
    lua_setfield(L, table, "ttl");

    return 1;
}

static int decode_data_set_mplshdr_fields(lua_State* L)
{
    auto dd = Interface::get_userdata<type>(L, tname, 1);

    int table = 2;
    luaL_checktype(L, table, LUA_TTABLE);

    lua_getfield(L, table, "label");
    if ( lua_isnumber(L, -1) )
        dd->mplsHdr.label = lua_tointeger(L, -1);

    // Need to keep popping to prevent stack from unnecessarily growing
    lua_pop(L, 1);

    lua_getfield(L, table, "exp");
    if ( lua_isnumber(L, -1) )
        dd->mplsHdr.exp = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "bos");
    if ( lua_isnumber(L, -1) )
        dd->mplsHdr.bos = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "ttl");
    if ( lua_isnumber(L, -1) )
        dd->mplsHdr.ttl = lua_tointeger(L, -1);

    return 0;
}

static int decode_data_reset(lua_State* L)
{
    auto dd = Interface::get_userdata<type>(L, tname, 1);
    dd->reset();

    return 0;
}

static int decode_data_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static int decode_data_destroy(lua_State* L)
{
    delete Interface::get_userdata<type>(L, tname, 1);
    return 0;
}

static const luaL_reg methods[] =
{
    { "new", decode_data_new },
    { "get_fields", decode_data_get_fields },
    { "set_fields", decode_data_set_fields },
    { "get_mplshdr_fields", decode_data_get_mplshdr_fields },
    { "set_mplshdr_fields", decode_data_set_mplshdr_fields },
    { "reset", decode_data_reset },
    { nullptr, nullptr }
};

static const luaL_reg metamethods[] =
{
    { "__gc", decode_data_destroy },
    { "__tostring", decode_data_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    methods,
    metamethods
};
} // namespace DecodeDataLib

//-------------------------------------------------------------------------
// Lua Packet Interface
//-------------------------------------------------------------------------

namespace PacketLib
{
const char* tname = "Packet";

static int packet_new(lua_State* L)
{
    auto rb = Interface::get_userdata<RawBufferLib::type>
            (L, RawBufferLib::tname, 1);

    size_t payload_start = check_size_param(L, 2, rb->size());
    size_t payload_end = opt_size_param(L, 3, rb->size(), rb->size());

    if ( payload_end < payload_start )
        luaL_error(L, "payload end must be greater than payload start");

    auto t = Interface::create_userdata<type>(L, tname);
    *t = new type();

    (*t)->reset();
    (*t)->pkt = reinterpret_cast<uint8_t*>(&rb->data()[0]);
    // FIXIT-L: add ability to change DAQ flags
    // This *must* be freed upon __gc
    (*t)->pkth = cooked_daq_pkthdr(rb->size());
    (*t)->data = reinterpret_cast<uint8_t*>(&rb->data()[payload_start]);
    (*t)->dsize = payload_end - payload_start;

    return 1;
}

static int packet_get_fields(lua_State* L)
{
    auto p = Interface::get_userdata<type>(L, tname, 1);

    lua_newtable(L);
    int table = lua_gettop(L);

    lua_pushinteger(L, p->packet_flags);
    lua_setfield(L, table, "packet_flags");

    lua_pushinteger(L, p->xtradata_mask);
    lua_setfield(L, table, "xtradata_mask");

    lua_pushinteger(L, p->proto_bits);
    lua_setfield(L, table, "proto_bits");

    lua_pushinteger(L, p->application_protocol_ordinal);
    lua_setfield(L, table, "application_protocol_ordinal");

    lua_pushinteger(L, p->alt_dsize);
    lua_setfield(L, table, "alt_dsize");

    lua_pushinteger(L, p->num_layers);
    lua_setfield(L, table, "num_layers");

    lua_pushinteger(L, p->ip_proto_next);
    lua_setfield(L, table, "ip_proto_next");

    return 1;
}

static int packet_set_fields(lua_State* L)
{
    auto p = Interface::get_userdata<type>(L, tname, 1);

    luaL_checktype(L, 2, LUA_TTABLE);
    int table = lua_gettop(L);

    lua_getfield(L, table, "packet_flags");
    if ( lua_isnumber(L, -1) )
        p->packet_flags = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "xtradata_mask");
    if ( lua_isnumber(L, -1) )
        p->xtradata_mask = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "proto_bits");
    if ( lua_isnumber(L, -1) )
        p->proto_bits = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "application_protocol_ordinal");
    if ( lua_isnumber(L, -1) )
        p->application_protocol_ordinal = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "alt_dsize");
    if ( lua_isnumber(L, -1) )
        p->alt_dsize = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "num_layers");
    if ( lua_isnumber(L, -1) )
        p->num_layers = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "ip_proto_next");
    if ( lua_isnumber(L, -1) )
        p->ip_proto_next = lua_tointeger(L, -1);

    return 0;
}

static int packet_set_decode_data(lua_State* L)
{
    auto p = Interface::get_userdata<type>(L, tname, 1);
    auto dd = Interface::get_userdata<DecodeDataLib::type>
            (L, DecodeDataLib::tname, 2);

    p->ptrs = *dd;
    return 0;
}

static int packet_reset(lua_State* L)
{
    auto p = Interface::get_userdata<type>(L, tname, 1);
    p->reset();

    return 0;
}

static int packet_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static int packet_destroy(lua_State* L)
{
    auto p = Interface::get_userdata<type>(L, tname, 1);
    delete p->pkth;
    delete p;

    return 0;
}

static const luaL_reg packet_methods[] =
{
    { "new", packet_new },
    { "get_fields", packet_get_fields },
    { "set_fields", packet_set_fields },
    { "set_decode_data", packet_set_decode_data },
    { "reset", packet_reset },
    { nullptr, nullptr }
};

static const luaL_reg packet_metamethods[] =
{
    { "__gc", packet_destroy },
    { "__tostring", packet_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    packet_methods,
    packet_metamethods
};
} // namespace PacketLib

struct _daq_pkthdr* cooked_daq_pkthdr(uint32_t pktlen, uint32_t flags)
{
    struct _daq_pkthdr* daq_hdr = new struct _daq_pkthdr;
    daq_hdr->pktlen = pktlen;
    daq_hdr->flags = flags;
    return daq_hdr;
}

size_t check_size_param(lua_State* L, int narg, size_t max)
{
    lua_Integer value = luaL_checkinteger(L, narg);
    if ( value < 0 || static_cast<size_t>(value) > max )
        luaL_argerror(L, narg, "out of bounds");

    return static_cast<size_t>(value);
}

size_t opt_size_param(lua_State* L, int narg, lua_Integer d, size_t max)
{
    lua_Integer value = luaL_optinteger(L, narg, d);
    if ( value < 0 || static_cast<size_t>(value) > max )
        luaL_argerror(L, narg, "out of bounds");

    return static_cast<size_t>(value);
}

} // namespace Piglet

