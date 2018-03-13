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
// pp_search_engine.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/mpse_manager.h"
#include "piglet/piglet_api.h"

#include "pp_search_engine_iface.h"

using namespace snort;

class SearchEnginePiglet : public Piglet::BasePlugin
{
public:
    SearchEnginePiglet(Lua::State&, const std::string&, Module*, SnortConfig*);
    ~SearchEnginePiglet() override;
    bool setup() override;

private:
    MpseWrapper* wrapper;
};

SearchEnginePiglet::SearchEnginePiglet(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc) :
    BasePlugin(state, target, m, sc)
{ wrapper = MpseManager::instantiate(target.c_str(), module, snort_conf); }

SearchEnginePiglet::~SearchEnginePiglet()
{
    if ( wrapper )
        delete wrapper;
}

bool SearchEnginePiglet::setup()
{
    if ( !wrapper )
        return true;

    install(L, SearchEngineIface, wrapper->instance);

    return false;
}

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------
static Piglet::BasePlugin* ctor(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc)
{ return new SearchEnginePiglet(state, target, m, sc); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api piglet_api =
{
    {
        PT_PIGLET,
        sizeof(Piglet::Api),
        PIGLET_API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_search_engine",
        "Search engine piglet",
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_SEARCH_ENGINE
};

const BaseApi* pp_search_engine = &piglet_api.base;
