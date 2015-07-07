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
// pp_ips_action.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <luajit-2.0/lua.hpp>

#include "piglet_plugin_common.h"
#include "piglet/piglet_api.h"
#include "helpers/lua.h"
#include "managers/action_manager.h"
#include "managers/module_manager.h"
#include "main/snort_config.h"
#include "framework/module.h"
#include "framework/ips_action.h"

namespace IpsActionPiglet
{
using namespace Lua;
using namespace PigletCommon;

// -----------------------------------------------------------------------------
// Lua Interface for IpsAction instance
// -----------------------------------------------------------------------------
namespace Instance
{
static int instance_exec(lua_State* L)
{
    auto p = Interface::get_userdata<PacketLib::type>
        (L, PacketLib::tname, 1);

    auto i = Util::regurgitate_instance<IpsAction>(L, 1);

    i->exec(p);

    return 0;
}

static int instance_get_name(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsAction>(L, 1);
    lua_pushstring(L, i->get_name());

    return 1;
}

static int instance_get_action(lua_State* L)
{
    auto i = Util::regurgitate_instance<IpsAction>(L, 1);
    lua_pushinteger(L, i->get_action());

    return 1;
}

static const luaL_reg methods[] =
{
    {"exec", instance_exec},
    {"get_name", instance_get_name},
    {"get_action", instance_get_action},
    { nullptr, nullptr }
};
} // namespace Instance

// -----------------------------------------------------------------------------
// Plugin foo
// -----------------------------------------------------------------------------

class Plugin : public Piglet::BasePlugin
{
public:
    Plugin(Lua::Handle&, std::string);
    virtual ~Plugin() override;
    virtual bool setup() override;

private:
    IpsActionWrapper* wrapper;
};

Plugin::Plugin(Lua::Handle& handle, std::string target) :
    BasePlugin(handle, target)
{
    auto m = ModuleManager::get_default_module(target.c_str(), snort_conf);
    // m != nullptr is guaranteed
    if ( !m )
        return;

    wrapper = ActionManager::instantiate(target.c_str(), m);
}

Plugin::~Plugin()
{
    // FIXIT: delete nullptr may be well defined,
    //       in which case, we don't need this check (look it up)
    if ( wrapper )
        delete wrapper;
}

bool Plugin::setup()
{
    if ( !wrapper )
        return true;

    lua_State* L = lua.get_state();

    Lua::Interface::register_lib(L, &PacketLib::lib);

    Util::register_instance_lib(
        L, Instance::methods, "IpsAction", wrapper->instance
        );

    return false;
}
} // namespace IpsActionPiglet

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------

static Piglet::BasePlugin* ctor(Lua::Handle& handle, std::string target, Module*)
{ return new IpsActionPiglet::Plugin(handle, target); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api ips_action_piglet_api =
{
    {
        PT_PIGLET,
        Piglet::API_SIZE,
        Piglet::API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_ips_action",
        Piglet::API_HELP,
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_IPS_ACTION
};

#ifdef BUILDING_SO

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ips_action_piglet_api.base,
    nullptr
};

#else

const BaseApi* pp_ips_action = &ips_action_piglet_api.base;

#endif

