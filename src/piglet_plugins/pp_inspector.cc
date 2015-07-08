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
// pp_inspector.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <luajit-2.0/lua.hpp>

#include "framework/module.h"
#include "framework/inspector.h"
#include "helpers/lua.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "piglet/piglet_api.h"

#include "piglet_plugin_common.h"

namespace InspectorPiglet
{
using namespace Lua;
using namespace PigletCommon;

// -----------------------------------------------------------------------------
// Lua Interface for Inspector instance
// -----------------------------------------------------------------------------
namespace Instance
{
static int instance_show(lua_State* L)
{
    auto i = Util::regurgitate_instance<Inspector>(L, 1);
    i->show(snort_conf);

    return 0;
}

static int instance_eval(lua_State* L)
{
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 1);
    auto i = Util::regurgitate_instance<Inspector>(L, 1);
    i->eval(p);

    return 0;
}

static int instance_clear(lua_State* L)
{
    auto p = Interface::get_userdata<PacketLib::type>(L, PacketLib::tname, 1);
    auto i = Util::regurgitate_instance<Inspector>(L, 1);
    i->clear(p);

    return 0;
}

static const luaL_reg methods[] =
{
    { "show", instance_show },
    { "eval", instance_eval },
    { "clear", instance_clear },
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
    InspectorWrapper* wrapper;
};

Plugin::Plugin(Lua::Handle& handle, std::string target) :
    BasePlugin(handle, target)
{
    auto m = ModuleManager::get_default_module(target.c_str(), snort_conf);
    if ( !m )
        return;

    wrapper = InspectorManager::instantiate(target.c_str(), m);
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

    lua_State* L = lua.get_state();

    Interface::register_lib(L, &RawBufferLib::lib);
    Interface::register_lib(L, &DecodeDataLib::lib);
    Interface::register_lib(L, &PacketLib::lib);

    Util::register_instance_lib(
        L, Instance::methods, "Inspector", wrapper->instance
        );

    return false;
}
} // namespace InspectorPiglet

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------

static Piglet::BasePlugin* ctor(Lua::Handle& handle, std::string target, Module*)
{ return new InspectorPiglet::Plugin(handle, target); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api inspector_piglet_api =
{
    {
        PT_PIGLET,
        Piglet::API_SIZE,
        Piglet::API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_inspector",
        Piglet::API_HELP,
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_INSPECTOR
};

#ifdef BUILDING_SO

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &inspector_piglet_api.base,
    nullptr
};

#else

const BaseApi* pp_inspector = &inspector_piglet_api.base;

#endif

