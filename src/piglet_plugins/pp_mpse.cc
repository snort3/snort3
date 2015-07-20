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
// pp_mpse.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <luajit-2.0/lua.hpp>

#include "piglet_plugin_common.h"
#include "piglet/piglet_api.h"
#include "helpers/lua.h"
#include "managers/mpse_manager.h"
#include "managers/module_manager.h"
#include "main/snort_config.h"
#include "framework/module.h"
#include "framework/mpse.h"

namespace MpsePiglet
{
using namespace Lua;
using namespace PigletCommon;

// -----------------------------------------------------------------------------
// Lua Interface for Mpse instance
// -----------------------------------------------------------------------------
namespace Instance
{
static const luaL_reg methods[] =
{
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
    MpseWrapper* wrapper;
};

Plugin::Plugin(Lua::State& state, std::string target) :
    BasePlugin(state, target)
{
    auto m = ModuleManager::get_default_module(target.c_str(), snort_conf);
    wrapper = MpseManager::instantiate(target.c_str(), m);
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

    Util::register_instance_lib(
        L, Instance::methods, "SearchEngine", wrapper->instance
        );

    return false;
}
} // namespace MpsePiglet

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------

static Piglet::BasePlugin* ctor(Lua::State& state, std::string target, Module*)
{ return new MpsePiglet::Plugin(state, target); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api mpse_piglet_api =
{
    {
        PT_PIGLET,
        Piglet::API_SIZE,
        Piglet::API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_mpse",
        Piglet::API_HELP,
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_SEARCH_ENGINE
};

#ifdef BUILDING_SO

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &mpse_piglet_api.base,
    nullptr
};

#else

const BaseApi* pp_mpse = &mpse_piglet_api.base;

#endif

