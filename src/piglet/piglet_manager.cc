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
// piglet_manager.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_manager.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <map>
#include <string>
#include <vector>

#include "log/messages.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"

namespace Piglet
{
using namespace std;

// -----------------------------------------------------------------------------
// Manager State
// -----------------------------------------------------------------------------

map<PlugType, Api*> plugins;
vector<Chunk> chunks;

// -----------------------------------------------------------------------------
// Static Definitions
// -----------------------------------------------------------------------------

static Api* find_plugin(PlugType key)
{
    auto search = plugins.find(key);
    if ( search != plugins.end() )
        return search->second;

    return nullptr;
}

// -----------------------------------------------------------------------------
// Public Methods
// -----------------------------------------------------------------------------

void Manager::init()
{
    chunks.clear();
    plugins.clear();
}

// FIXIT-M: Deal with case where 2 plugins have the same target (version priority?)
void Manager::add_plugin(Api* api)
{ plugins[api->target] = api; }

BasePlugin* Manager::instantiate(Lua::State& lua, string type, string target)
{
    auto key = PluginManager::get_type(type.c_str());
    if ( key == PT_MAX )
    {
        ErrorMessage("piglet: '%s' is not a valid plugin type\n", type.c_str());
        return nullptr;
    }

    Module* m = ModuleManager::get_module(target.c_str());

    auto api = find_plugin(key);
    if ( !api )
    {
        ErrorMessage("piglet: no piglet found for plugin type '%s'\n", type.c_str());
        return nullptr;
    }

    auto p = api->ctor(lua, target, m);
    if ( !p )
    {
        ErrorMessage(
            "piglet: couldn't instantiate piglet for plugin type '%s'\n",
            type.c_str()
            );

        return nullptr;
    }

    p->set_api(api);
    return p;
}

void Manager::destroy(BasePlugin* p)
{
    if ( p )
    {
        auto api = p->get_api();
        if ( api && api->dtor )
            api->dtor(p);
    }
}

void Manager::add_chunk(string filename, string chunk)
{ chunks.push_back(Chunk(filename, chunk)); }

const vector<Chunk>& Manager::get_chunks()
{ return chunks; }
} // namespace Piglet

