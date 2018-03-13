//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// plugin_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugin_manager.h"

#include <dlfcn.h>
#include <sys/stat.h>

#include <iostream>
#include <map>

#include "framework/codec.h"
#include "framework/connector.h"
#include "framework/logger.h"
#include "framework/mpse.h"
#include "helpers/directory.h"
#include "helpers/markup.h"
#include "log/messages.h"

#ifdef PIGLET
#include "piglet/piglet_api.h"
#include "piglet/piglet_manager.h"
#endif

#include "action_manager.h"
#include "codec_manager.h"
#include "connector_manager.h"
#include "event_manager.h"
#include "inspector_manager.h"
#include "ips_manager.h"
#include "module_manager.h"
#include "mpse_manager.h"
#include "script_manager.h"
#include "so_manager.h"

using namespace snort;
using namespace std;

#define lib_pattern "*.so"

struct Symbol
{
    const char* name;
    unsigned version;
    unsigned size;
};

#if 1
// sequence must match PlugType definition
// compiler catches too many but not too few
static Symbol symbols[PT_MAX] =
{
    { "codec", CDAPI_VERSION, sizeof(CodecApi) },
    { "inspector", INSAPI_VERSION, sizeof(InspectApi) },
    { "ips_action", ACTAPI_VERSION, sizeof(ActionApi) },
    { "ips_option", IPSAPI_VERSION, sizeof(IpsApi) },
    { "search_engine", SEAPI_VERSION, sizeof(MpseApi) },
    { "so_rule", SOAPI_VERSION, sizeof(SoApi) },
    { "logger", LOGAPI_VERSION, sizeof(LogApi) },
    { "connector", CONNECTOR_API_VERSION, sizeof(ConnectorApi) }
#ifdef PIGLET
    ,
    { "piglet", PIGLET_API_VERSION, sizeof(Piglet::Api) }
#endif
};
#else
// this gets around the sequence issue with some compilers
// but does not fail if we are missing an entry :(
#define stringify(name) # name
static Symbol symbols[PT_MAX] =
{
    [PT_CODEC] = { stringify(PT_CODEC), CDAPI_VERSION, sizeof(CodecApi) },
    [PT_INSPECTOR] = { stringify(PT_INSPECTOR), INSAPI_VERSION, sizeof(InspectApi) },
    [PT_IPS_ACTION] = { stringify(PT_IPS_ACTION), ACTAPI_VERSION, sizeof(ActionApi) },
    [PT_IPS_OPTION] = { stringify(PT_IPS_OPTION), IPSAPI_VERSION, sizeof(IpsApi) },
    [PT_SEARCH_ENGINE] = { stringify(PT_SEARCH_ENGINE), SEAPI_VERSION, sizeof(MpseApi) },
    [PT_SO_RULE] = { stringify(PT_SO_RULE), SOAPI_VERSION, sizeof(SoApi) },
    [PT_LOGGER] = { stringify(PT_LOGGER), LOGAPI_VERSION, sizeof(LogApi) }
};
#endif

PlugType PluginManager::get_type(const char* s)
{
    for ( int i = 0; i < PT_MAX; i++ )
        if ( !strcmp(s, symbols[i].name) )
            return (PlugType)i;

    return PT_MAX;
}

const char* PluginManager::get_type_name(PlugType pt)
{
    if ( pt >= PT_MAX )
        return "error";

    return symbols[pt].name;
}

static const char* current_plugin = nullptr;

const char* PluginManager::get_current_plugin()
{ return current_plugin; }

struct Plugin
{
    string source;
    string key;

    const BaseApi* api;
    void* handle;

    Plugin()
    { clear(); }

    void clear()
    { source.clear(); key.clear(); api = nullptr; handle = nullptr; }
};

typedef std::map<string, Plugin> PlugMap;
static PlugMap plug_map;

struct RefCount
{
    unsigned count;

    RefCount() { count = 0; }

    //~RefCount() { assert(!count); }; // FIXIT-L fails on fatal error
};

typedef std::map<void*, RefCount> RefMap;
static RefMap ref_map;

static void set_key(string& key, Symbol* sym, const char* name)
{
    key = sym->name;
    key += "::";
    key += name;
}

// plugins are linked when loaded (RTLD_NOW) so missing symbols
// don't make it this far.  we therefore only need to check
// that shared structs are defined identically, so opts strings
// must be identical.
static bool compatible_builds(const char* plug_opts)
{
    const char* snort_opts = API_OPTIONS;

    if ( !snort_opts and !plug_opts )
        return true;

    if ( !snort_opts or !plug_opts )
        return false;

    if ( strcmp(snort_opts, plug_opts) )
        return false;

    return true;
}

static bool register_plugin(
    const BaseApi* api, void* handle, const char* file)
{
    if ( api->type >= PT_MAX )
        return false;

    Symbol* sym = symbols + api->type;

    if ( api->size != sym->size )
    {
        ParseWarning(WARN_PLUGINS, "%s: size mismatch; expected %u, got %u",
            api->name, sym->size, api->size);
        return false;
    }

    if ( api->api_version != sym->version )
    {
        ParseWarning(WARN_PLUGINS, "%s: version mismatch; expected %u, got %u",
            api->name, sym->version, api->version);
        return false;
    }

    if ( !compatible_builds(api->options) )
    {
        ParseWarning(WARN_PLUGINS, "%s: incompatible builds", api->name);
        return false;
    }

    // validate api ?

    string key;
    set_key(key, sym, api->name);

    Plugin& p = plug_map[key];

    if ( p.api )
    {
        if ( p.api->version >= api->version)
            return false;  // keep the old one

        if ( p.handle && !--ref_map[p.handle].count )
            dlclose(p.handle); // drop the old one
    }

    p.key = key;
    p.api = api;
    p.handle = handle;
    p.source = file;

    if ( handle )
        ++ref_map[handle].count;

    return true;
}

static void load_list(
    const BaseApi** api, void* handle = nullptr, const char* file = "static")
{
    bool keep = false;

    while ( *api )
    {
        keep = register_plugin(*api, handle, file) || keep;
        //printf("loaded %s\n", (*api)->name);
        ++api;
    }
    if ( handle && !keep )
        dlclose(handle);
}

static bool load_lib(const char* file)
{
    struct stat fs;
    void* handle;

    if ( stat(file, &fs) || !(fs.st_mode & S_IFREG) )
        return false;

    if ( !(handle = dlopen(file, RTLD_NOW|RTLD_LOCAL)) )
    {
        if ( const char* err = dlerror() )
            ParseWarning(WARN_PLUGINS, "%s (%s)", err, file);
        return false;
    }
    const BaseApi** api = (const BaseApi**)dlsym(handle, "snort_plugins");

    if ( !api )
    {
        if ( const char* err = dlerror() )
            ParseWarning(WARN_PLUGINS, "%s (%s)", err, file);

        dlclose(handle);
        return false;
    }
    load_list(api, handle, file);
    return true;
}

static void add_plugin(Plugin& p)
{
    Module* m = nullptr;
    if ( p.api->mod_ctor )
    {
        current_plugin = p.api->name;
        m = p.api->mod_ctor();
        ModuleManager::add_module(m, p.api);
    }

    switch ( p.api->type )
    {
    case PT_CODEC:
        CodecManager::add_plugin((const CodecApi*)p.api);
        break;

    case PT_INSPECTOR:
        // probes must always be global. they run regardless of selected policy.
        assert( (m && ((const InspectApi*)p.api)->type == IT_PROBE) ? 
                m->get_usage() == Module::GLOBAL :
                true );

        InspectorManager::add_plugin((const InspectApi*)p.api);
        break;

    case PT_IPS_ACTION:
        ActionManager::add_plugin((const ActionApi*)p.api);
        break;

    case PT_IPS_OPTION:
        IpsManager::add_plugin((const IpsApi*)p.api);
        break;

    case PT_SEARCH_ENGINE:
        MpseManager::add_plugin((const MpseApi*)p.api);
        break;

    case PT_SO_RULE:
        SoManager::add_plugin((const SoApi*)p.api);
        break;

    case PT_LOGGER:
        EventManager::add_plugin((const LogApi*)p.api);
        break;

    case PT_CONNECTOR:
        ConnectorManager::add_plugin((const ConnectorApi*)p.api);
        break;

#ifdef PIGLET
    case PT_PIGLET:
        Piglet::Manager::add_plugin((const Piglet::Api*)p.api);
        break;
#endif

    default:
        assert(false);
        break;
    }
}

static void load_plugins(const std::string& paths)
{
    const char* t = paths.c_str();
    vector<char> buf(t, t+strlen(t)+1);
    char* last;

    char* s = strtok_r(&buf[0], ":", &last);

    while ( s )
    {
        Directory d(s, lib_pattern);
        const char* f;

        while ( (f = d.next()) )
            load_lib(f);

        s = strtok_r(nullptr, ":", &last);
    }
}

static void add_plugins()
{
    PlugMap::iterator it;

    for ( it = plug_map.begin(); it != plug_map.end(); ++it )
        add_plugin(it->second);
}

static void unload_plugins()
{
    for ( PlugMap::iterator it = plug_map.begin(); it != plug_map.end(); ++it )
    {
        if ( it->second.handle )
            --ref_map[it->second.handle].count;

        it->second.clear();
    }

#ifndef REG_TEST
    for ( RefMap::iterator it = ref_map.begin(); it != ref_map.end(); ++it )
        dlclose(it->first);
#endif
}

//-------------------------------------------------------------------------
// framework methods
//-------------------------------------------------------------------------

void PluginManager::load_plugins(const BaseApi** lp)
{
    // builtins
    load_list(lp);
}

void PluginManager::load_plugins(const std::string& paths)
{
    // dynamic plugins
    if ( !paths.empty() )
        ::load_plugins(paths);

    // script plugins
    // FIXIT-L need path to script for --list-plugins
    load_list(ScriptManager::get_plugins());

    add_plugins();
}

void PluginManager::list_plugins()
{
    PlugMap::iterator it;

    for ( it = plug_map.begin(); it != plug_map.end(); ++it )
    {
        Plugin& p = it->second;
        cout << Markup::item();
        cout << Markup::escape(p.key);
        cout << " v" << p.api->version;
        cout << " " << p.source;
        cout << endl;
    }
}

void PluginManager::show_plugins()
{
    PlugMap::iterator it;

    for ( it = plug_map.begin(); it != plug_map.end(); ++it )
    {
        Plugin& p = it->second;

        cout << Markup::item();
        cout << Markup::emphasis(p.key);
        cout << ": " << p.api->help << endl;
    }
}

void PluginManager::dump_plugins()
{
    CodecManager::dump_plugins();
    InspectorManager::dump_plugins();
    MpseManager::dump_plugins();
    IpsManager::dump_plugins();
    SoManager::dump_plugins();
    ActionManager::dump_plugins();
    EventManager::dump_plugins();
    ConnectorManager::dump_plugins();
}

void PluginManager::release_plugins()
{
    EventManager::release_plugins();
    ActionManager::release_plugins();
    InspectorManager::release_plugins();
    IpsManager::release_plugins();
    SoManager::release_plugins();
    MpseManager::release_plugins();
    CodecManager::release_plugins();
    ConnectorManager::release_plugins();

    unload_plugins();
}

const BaseApi* PluginManager::get_api(PlugType type, const char* name)
{
    if ( type >= PT_MAX )
        return nullptr;

    string key;
    set_key(key, symbols+type, name);

    const PlugMap::iterator it = plug_map.find(key);

    if ( it != plug_map.end() )
        return it->second.api;

    return nullptr;
}

#ifdef PIGLET
PlugType PluginManager::get_type_from_name(const std::string& name)
{
    for ( auto it = plug_map.begin(); it != plug_map.end(); ++it )
    {
        const auto* api = it->second.api;
        if ( name == api->name )
            return api->type;
    }

    return PT_MAX;
}

#endif

void PluginManager::instantiate(
    const BaseApi* api, Module* mod, SnortConfig* sc)
{
    switch ( api->type )
    {
    case PT_CODEC:
        CodecManager::instantiate((const CodecApi*)api, mod, sc);
        break;

    case PT_INSPECTOR:
        InspectorManager::instantiate((const InspectApi*)api, mod, sc);
        break;

    case PT_IPS_ACTION:
        ActionManager::instantiate((const ActionApi*)api, mod, sc);
        break;

    case PT_IPS_OPTION:
        // do not instantiate here; done later
        //IpsManager::instantiate((IpsApi*)api, mod, sc);
        break;

    case PT_SEARCH_ENGINE:
        MpseManager::instantiate((const MpseApi*)api, mod, sc);
        break;

    case PT_CONNECTOR:
        ConnectorManager::instantiate((const ConnectorApi*)api, mod, sc);
        break;

    case PT_SO_RULE:
        // do not instantiate here; done later
        //IpsManager::instantiate((SoApi*)api, mod, sc);
        break;

    case PT_LOGGER:
        EventManager::instantiate((const LogApi*)api, mod, sc);
        break;

    default:
        assert(false);
        break;
    }
}

void PluginManager::instantiate(
    const BaseApi* api, Module* mod, SnortConfig* sc, const char* name)
{
    if ( api->type == PT_INSPECTOR )
        InspectorManager::instantiate((const InspectApi*)api, mod, sc, name);

    else
        assert(false);
}

const char* PluginManager::get_available_plugins(PlugType t)
{
    static std::string s;
    s.clear();

    for ( auto it = plug_map.begin(); it != plug_map.end(); ++it )
    {
        const auto* api = it->second.api;

        if ( t != api->type )
            continue;

        if ( !s.empty() )
            s += " | ";

        s += api->name;
    }
    return s.c_str();
}

