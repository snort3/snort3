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
// piglet_manager.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "piglet_manager.h"

#include <cassert>

#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"

#include "piglet_api.h"
#include "piglet_utils.h"

#define PLUGIN_KEY_SEP "::"

namespace snort
{
class Module;
}

namespace Piglet
{
using namespace snort;
using namespace std;

// -----------------------------------------------------------------------------
// Manager State
// -----------------------------------------------------------------------------

std::map<PlugType, const Api*> plugins;
vector<Chunk> chunks;

// -----------------------------------------------------------------------------
// Static Definitions
// -----------------------------------------------------------------------------

static void split_key(const string& key, string& type, string& name)
{
    type.clear();
    name.clear();

    auto split = key.find(PLUGIN_KEY_SEP);

    // If there is no split, assume that 'key' only contains plugin name
    if ( split == string::npos )
    {
        name = key;
    }
    else
    {
        type = key.substr(0, split);
        name = key.substr(split + 2);
    }
}

static const Api* find_piglet(PlugType key)
{
    auto search = plugins.find(key);
    if ( search != plugins.end() )
        return search->second;

    return nullptr;
}

static BasePlugin* instantiate(
    Lua::State& lua, PlugType key, std::string name, bool use_defaults)
{
    auto piglet_api = find_piglet(key);

    if ( !piglet_api )
    {
        ErrorMessage(
            "piglet: no handler found for plugin type '%s'\n",
            PluginManager::get_type_name(key)
        );

        return nullptr;
    }

    Module* m;
    if ( key == PT_IPS_OPTION || use_defaults )
        // FIXIT-L this is just a workaround, need to be able to get parsed rule module
        m = ModuleManager::get_default_module(name.c_str(), SnortConfig::get_conf());
    else
        m = ModuleManager::get_module(name.c_str());

    auto piglet = piglet_api->ctor(lua, name, m, SnortConfig::get_conf());

    assert(piglet);

    piglet->set_api(piglet_api);
    return piglet;
}

// -----------------------------------------------------------------------------
// Public Methods
// -----------------------------------------------------------------------------

void Manager::init()
{
    chunks.clear();
    plugins.clear();
}

// FIXIT-M deal with case where 2 plugins have the same target (version priority?)
void Manager::add_plugin(const Api* api)
{ plugins[api->target] = api; }

BasePlugin* Manager::instantiate(
    Lua::State& lua, const string& target,
    string& type, string& name, bool use_defaults)
{
    PlugType pt = PT_MAX;
    split_key(target, type, name);

    if ( !type.empty() )
        pt = PluginManager::get_type(type.c_str());
    else if ( !name.empty() )
        pt = PluginManager::get_type_from_name(target);
    else
    {
        ErrorMessage(
            "piglet: invalid plugin specified: '%s'\n", target.c_str());
        return nullptr;
    }

    if ( pt == PT_MAX )
    {
        ErrorMessage(
            "piglet: could not find plugin '%s::%s'",
            type.c_str(), name.c_str()
        );

        return nullptr;
    }

    return ::Piglet::instantiate(lua, pt, name, use_defaults);
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

void Manager::add_chunk(const string& filename, const string& target, const string& chunk)
{ chunks.push_back(Chunk(filename, target, chunk)); }

const vector<Chunk>& Manager::get_chunks()
{ return chunks; }
} // namespace Piglet

