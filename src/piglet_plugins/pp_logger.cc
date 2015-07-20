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
// pp_logger.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <luajit-2.0/lua.hpp>

#include "piglet_plugin_common.h"
#include "piglet/piglet_api.h"
#include "helpers/lua.h"
#include "managers/event_manager.h"
#include "managers/module_manager.h"
#include "main/snort_config.h"
#include "framework/module.h"

namespace LoggerPiglet
{
using namespace std;
using namespace Lua;
using namespace PigletCommon;

//-------------------------------------------------------------------------
// Lua Event Interface
//-------------------------------------------------------------------------

namespace EventLib
{

struct EventWrapper
{
    Event event;
    SigInfo sig_info;

    EventWrapper()
    { event.sig_info = &sig_info; }
};

using type = EventWrapper;
const char* tname = "Event";

static int event_new(lua_State* L)
{
    auto t = Interface::create_userdata<type>(L, tname);
    *t = new type;

    return 1;
}

static int event_get_fields(lua_State* L)
{
    auto e = Interface::get_userdata<type>(L, tname, 1);

    lua_newtable(L);
    int table = lua_gettop(L);

    lua_pushinteger(L, e->event.event_id);
    lua_setfield(L, table, "event_id");

    lua_pushinteger(L, e->event.event_reference);
    lua_setfield(L, table, "event_reference");

    if ( e->event.alt_msg )
    {
        lua_pushstring(L, e->event.alt_msg);
        lua_setfield(L, table, "alt_msg");
    }

    return 1;
}

static int event_set_fields(lua_State* L)
{
    auto e = Interface::get_userdata<type>(L, tname, 1);

    int table = 2;
    luaL_checktype(L, table, LUA_TTABLE);

    lua_getfield(L, table, "event_id");
    if ( lua_isnumber(L, -1) )
        e->event.event_id = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "event_reference");
    if ( lua_isnumber(L, -1) )
        e->event.event_reference = lua_tointeger(L, -1);

    // FIXIT-L: Add ability to set string fields

    return 0;
}

static int event_get_siginfo_fields(lua_State* L)
{
    auto e = Interface::get_userdata<type>(L, tname, 1);

    lua_newtable(L);
    int table = lua_gettop(L);

    lua_pushinteger(L, e->sig_info.generator);
    lua_setfield(L, table, "generator");

    lua_pushinteger(L, e->sig_info.id);
    lua_setfield(L, table, "id");

    lua_pushinteger(L, e->sig_info.rev);
    lua_setfield(L, table, "rev");

    lua_pushinteger(L, e->sig_info.class_id);
    lua_setfield(L, table, "class_id");

    lua_pushinteger(L, e->sig_info.priority);
    lua_setfield(L, table, "priority");

    lua_pushboolean(L, e->sig_info.text_rule);
    lua_setfield(L, table, "text_rule");

    lua_pushinteger(L, e->sig_info.num_services);
    lua_setfield(L, table, "num_services");

    if ( e->sig_info.message )
    {
        lua_pushstring(L, e->sig_info.message);
        lua_setfield(L, table, "message");
    }

    return 1;
}

static int event_set_siginfo_fields(lua_State* L)
{
    auto e = Interface::get_userdata<type>(L, tname, 1);

    int table = 2;
    luaL_checktype(L, table, LUA_TTABLE);

    lua_getfield(L, table, "generator");
    if ( lua_isnumber(L, -1) )
        e->sig_info.generator = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "id");
    if ( lua_isnumber(L, -1) )
        e->sig_info.id = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "rev");
    if ( lua_isnumber(L, -1) )
        e->sig_info.rev = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "class_id");
    if ( lua_isnumber(L, -1) )
        e->sig_info.class_id = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "priority");
    if ( lua_isnumber(L, -1) )
        e->sig_info.priority = lua_tointeger(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "text_rule");
    e->sig_info.text_rule = lua_toboolean(L, -1);

    lua_pop(L, 1);

    lua_getfield(L, table, "num_services");
    if ( lua_isnumber(L, -1) )
        e->sig_info.num_services = lua_tointeger(L, -1);

    // FIXIT-L: Add ability to set string fields

    return 0;
}

static int event_destroy(lua_State* L)
{
    delete Interface::get_userdata<type>(L, tname, 1);
    return 0;
}

static int event_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static const luaL_reg methods[] =
{
    { "new", event_new },
    { "get_fields", event_get_fields },
    { "set_fields", event_set_fields },
    { "get_siginfo_fields", event_get_siginfo_fields },
    { "set_siginfo_fields", event_set_siginfo_fields },
    { nullptr, nullptr }
};

static const luaL_reg metamethods[] =
{
    { "__gc", event_destroy },
    { "__tostring", event_tostring },
    { nullptr, nullptr }
};

const Interface::Library lib =
{
    tname,
    methods,
    metamethods
};
} // namespace EventLib

// -----------------------------------------------------------------------------
// Lua Interface for Logger instance
// -----------------------------------------------------------------------------
namespace Instance
{
static int instance_alert(lua_State* L)
{
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 1);
    string message = luaL_checkstring(L, 2);
    auto e = Interface::get_userdata<EventLib::type>(L, EventLib::tname, 3);
    auto i = Util::regurgitate_instance<Logger>(L, 1);
    i->alert(p, message.c_str(), &e->event);

    return 0;
}

static int instance_log(lua_State* L)
{
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 1);
    string message = luaL_checkstring(L, 2);
    auto e = Interface::get_userdata<EventLib::type>(L, EventLib::tname, 3);
    auto i = Util::regurgitate_instance<Logger>(L, 1);
    i->log(p, message.c_str(), &e->event);

    return 0;
}

static int instance_open(lua_State* L)
{
    auto i = Util::regurgitate_instance<Logger>(L, 1);
    i->open();
    return 0;
}

static int instance_close(lua_State* L)
{
    auto i = Util::regurgitate_instance<Logger>(L, 1);
    i->close();
    return 0;
}

static int instance_reset(lua_State* L)
{
    auto i = Util::regurgitate_instance<Logger>(L, 1);
    i->reset();
    return 0;
}

static const luaL_reg methods[] =
{
    { "alert", instance_alert },
    { "log", instance_log },
    { "open", instance_open },
    { "close", instance_close },
    { "reset", instance_reset },
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
    LoggerWrapper* wrapper;
};

Plugin::Plugin(Lua::State& state, std::string target) :
    BasePlugin(state, target)
{
    auto m = ModuleManager::get_default_module(target.c_str(), snort_conf);
    if ( m )
        wrapper = EventManager::instantiate(target.c_str(), m, snort_conf);
}

Plugin::~Plugin()
{
    if ( wrapper )
        delete wrapper;
}

bool Plugin::setup()
{
    if ( !wrapper )
        return true;

    Interface::register_lib(L, &RawBufferLib::lib);
    Interface::register_lib(L, &PacketLib::lib);
    Interface::register_lib(L, &EventLib::lib);

    Util::register_instance_lib(
        L, Instance::methods, "Logger", wrapper->instance
        );

    return false;
}
} // namespace LoggerPiglet

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------

static Piglet::BasePlugin* ctor(Lua::State& state, std::string target, Module*)
{ return new LoggerPiglet::Plugin(state, target); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api logger_piglet_api =
{
    {
        PT_PIGLET,
        Piglet::API_SIZE,
        Piglet::API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_logger",
        Piglet::API_HELP,
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_LOGGER
};

#ifdef BUILDING_SO

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &logger_piglet_api.base,
    nullptr
};

#else

const BaseApi* pp_logger = &logger_piglet_api.base;

#endif

