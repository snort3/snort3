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
// pp_ips_option.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <luajit-2.0/lua.hpp>

#include "piglet_plugin_common.h"
#include "piglet/piglet_api.h"
#include "helpers/lua.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "main/snort_config.h"
#include "framework/module.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "detection/treenodes.h"

namespace IpsOptionPiglet
{
using namespace std;
using namespace Lua;
using namespace PigletCommon;

// -----------------------------------------------------------------------------
// Lua CursorLib Interface
// -----------------------------------------------------------------------------
namespace CursorLib
{
using type = Cursor;
const char* tname = "Cursor";

static int cursor_new(lua_State* L)
{
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 1);
    auto t = Interface::create_userdata<type>(L, tname);
    *t = new type(p);

    return 1;
}

static int cursor_get_name(lua_State* L)
{
    auto c = Interface::get_userdata<type>(L, tname, 1);
    lua_pushstring(L, c->get_name());

    return 1;
}

static int cursor_is(lua_State* L)
{
    auto c = Interface::get_userdata<type>(L, tname, 1);
    string s = luaL_checkstring(L, 2);
    lua_pushboolean(L, c->is(s.c_str()));

    return 1;
}

static int cursor_reset(lua_State* L)
{
    auto c = Interface::get_userdata<type>(L, tname, 1);
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 2);
    c->reset(p);

    return 1;
}

static int cursor_set(lua_State* L)
{
    auto c = Interface::get_userdata<type>(L, tname, 1);
    string name = luaL_checkstring(L, 2);
    auto rb = Interface::get_userdata<RawBufferLib::type>
        (L, RawBufferLib::tname, 3);

    unsigned size = luaL_checkinteger(L, 4);

    c->set(name.c_str(), reinterpret_cast<uint8_t*>(rb->data()), size);

    return 0;
}

static int cursor_tostring(lua_State* L)
{ return Util::tostring<type>(L, tname); }

static int cursor_destroy(lua_State* L)
{
    delete Interface::get_userdata<type>(L, tname, 1);
    return 0;
}

static const luaL_reg cursor_methods[] =
{
    { "new", cursor_new },
    { "get_name", cursor_get_name },
    { "is", cursor_is },
    { "reset", cursor_reset },
    { "set", cursor_set },
    { nullptr, nullptr }
};

static const luaL_reg cursor_metamethods[] =
{
    { "__gc", cursor_destroy },
    { "__tostring", cursor_tostring },
    { nullptr, nullptr }
};

const struct Interface::Library lib =
{
    tname,
    cursor_methods,
    cursor_metamethods
};
} // namespace CursorLib

// -----------------------------------------------------------------------------
// Lua Interface for IpsOption instance
// -----------------------------------------------------------------------------
namespace Instance
{
static int instance_hash(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    lua_pushinteger(L, i->hash());

    return 0;
}

static int instance_is_relative(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    lua_pushboolean(L, i->is_relative());

    return 1;
}

static int instance_fp_research(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    lua_pushboolean(L, i->fp_research());

    return 1;
}

static int instance_eval(lua_State* L)
{
    auto c = Interface::get_userdata<CursorLib::type>(L, CursorLib::tname, 1);
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 2);
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    int result = i->eval(*c, p);
    lua_pushinteger(L, result);

    return 1;
}

static int instance_action(lua_State* L)
{
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 1);
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    i->action(p);

    return 0;
}

static int instance_get_type(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    lua_pushinteger(L, i->get_type());

    return 1;
}

static int instance_get_name(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    lua_pushstring(L, i->get_name());

    return 1;
}

static int instance_get_cursor_type(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsOption>(L, 1);
    lua_pushinteger(L, i->get_cursor_type());

    return 1;
}

static const luaL_reg methods[] =
{
    { "hash", instance_hash },
    { "is_relative", instance_is_relative },
    { "fp_research", instance_fp_research },
    { "eval", instance_eval },
    { "action", instance_action },
    { "get_type", instance_get_type },
    { "get_name", instance_get_name },
    { "get_cursor_type", instance_get_cursor_type },
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
    IpsOptionWrapper* wrapper;
    struct OptTreeNode* otn;
};

Plugin::Plugin(Lua::State& state, std::string target) :
    BasePlugin(state, target)
{
    // FIXIT-M: Add logging so user knows what didn't work 
    auto m = ModuleManager::get_default_module(target.c_str(), snort_conf);
    if ( !m )
        return;

    otn = new struct OptTreeNode;
    if ( !otn )
        return;

    wrapper = IpsManager::instantiate(target.c_str(), m, otn);
}

Plugin::~Plugin()
{
    if ( wrapper )
        delete wrapper;

    if ( otn )
        delete otn;
}

bool Plugin::setup()
{
    if ( !wrapper )
        return true;

    Interface::register_lib(L, &RawBufferLib::lib);
    Interface::register_lib(L, &PacketLib::lib);
    Interface::register_lib(L, &CursorLib::lib);

    Util::register_instance_lib(
        L, Instance::methods, "IpsOption", wrapper->instance
        );

    return false;
}
} // namespace IpsOptionPiglet

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------

static Piglet::BasePlugin* ctor(Lua::State& state, std::string target, Module*)
{ return new IpsOptionPiglet::Plugin(state, target); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api ips_option_piglet_api =
{
    {
        PT_PIGLET,
        Piglet::API_SIZE,
        Piglet::API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_ips_option",
        Piglet::API_HELP,
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_IPS_OPTION
};

#ifdef BUILDING_SO

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ips_option_piglet_api.base,
    nullptr
};

#else

const BaseApi* pp_ips_option = &ips_option_piglet_api.base;

#endif

