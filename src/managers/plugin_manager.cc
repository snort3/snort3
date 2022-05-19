//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include <iostream>
#include <sstream>
#include <sys/stat.h>

#include "framework/codec.h"
#include "framework/connector.h"
#include "framework/logger.h"
#include "framework/mpse.h"
#include "framework/policy_selector.h"
#include "helpers/directory.h"
#include "helpers/markup.h"
#include "log/messages.h"
#include "main/snort_config.h"

#include "action_manager.h"
#include "codec_manager.h"
#include "connector_manager.h"
#include "event_manager.h"
#include "inspector_manager.h"
#include "ips_manager.h"
#include "module_manager.h"
#include "mpse_manager.h"
#include "policy_selector_manager.h"
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
    { "connector", CONNECTOR_API_VERSION, sizeof(ConnectorApi) },
    { "policy_selector", POLICY_SELECTOR_API_VERSION, sizeof(PolicySelectorApi) },
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
    [PT_LOGGER] = { stringify(PT_LOGGER), LOGAPI_VERSION, sizeof(LogApi) },
    [PT_CONNECTOR] = { stringify(PT_CONNECTOR), CONNECTOR_API_VERSION, sizeof(ConnectorApi) },
    [PT_POLICY_SELECTOR] = { stringify(PT_POLICY_SELECTOR), POLICY_SELECTOR_API_VERSION,
        sizeof(PolicySelectorApi) }
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
    const BaseApi* api = nullptr;
    SoHandlePtr handle;
};

Plugins::~Plugins()
{
    plug_map.clear();
}

SoHandle::~SoHandle()
{
#ifndef REG_TEST
    if ( handle )
        dlclose(handle);
#endif
}

static Plugins s_plugins;

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

static bool plugin_is_reloadable(const BaseApi* api)
{
    if ( api->type == PT_SO_RULE )
        return true;
    else
        return false;
}

static bool register_plugin(
    const BaseApi* api, SoHandlePtr handle, const char* file, SnortConfig* sc)
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
        ParseWarning(WARN_PLUGINS, "%s: version mismatch; expected 0x%x, got 0x%x",
            api->name, sym->version, api->api_version);
        return false;
    }

    if ( !compatible_builds(api->options) )
    {
        ParseWarning(WARN_PLUGINS, "%s: incompatible builds", api->name);
        return false;
    }

    if ( sc and !plugin_is_reloadable(api) )
        return false;

    string key;
    set_key(key, sym, api->name);

    Plugin& p = ( sc ? sc->plugins->plug_map[key] : s_plugins.plug_map[key] );
    if ( p.api )
    {
        if ( p.api->version > api->version )
            return false;  // keep the old one
    }

    p.key = key;
    p.api = api;
    p.handle = handle;
    p.source = file;

    return true;
}

static void load_list(
    const BaseApi** api, void* handle = nullptr, const char* file = "static", SnortConfig* sc = nullptr)
{
    SoHandlePtr so_file;
    if ( handle and sc )
    {   // for reload, if the so lib file was previously opened, reuse the shared_ptr
        for( auto const& i : s_plugins.plug_map )
        {
            if ( i.second.api == (*api) and i.second.handle.get()->handle == handle )
            {
                so_file = i.second.handle;
                break;
            }
        }
    }
    if ( !so_file.get() )
        so_file = std::make_shared<SoHandle>(handle);

    while ( *api )
    {
        register_plugin(*api, so_file, file, sc);
        ++api;
    }
}

static bool load_lib(const char* file, SnortConfig* sc)
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
    load_list(api, handle, file, sc);
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
        // SO rules are added later
        break;

    case PT_LOGGER:
        EventManager::add_plugin((const LogApi*)p.api);
        break;

    case PT_CONNECTOR:
        ConnectorManager::add_plugin((const ConnectorApi*)p.api);
        break;

    case PT_POLICY_SELECTOR:
        PolicySelectorManager::add_plugin((const PolicySelectorApi*)p.api);
        break;

    default:
        assert(false);
        break;
    }
}

static void load_plugins(const std::string& paths, SnortConfig* sc = nullptr)
{
    struct stat sb;
    stringstream paths_stream(paths);
    string segment;
    vector<string> path_list;

    while ( getline(paths_stream, segment, ':') )
        if ( segment.length() > 0 )
            path_list.push_back(segment);

    for ( auto& path : path_list )
    {
        if ( stat(path.c_str(), &sb) )
            continue;

        if ( sb.st_mode & S_IFDIR )
        {
            Directory d(path.c_str(), lib_pattern);

            while ( const char* f = d.next() )
                load_lib(f, sc);
        }
        else
        {
            if ( path.find("/") == string::npos )
                path = "./" + path;

            load_lib(path.c_str(), sc);
        }
    }
}

static void add_plugins()
{
    for ( auto it = s_plugins.plug_map.begin(); it != s_plugins.plug_map.end(); ++it )
        add_plugin(it->second);
}

static void unload_plugins()
{
    s_plugins.plug_map.clear();
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
    SoManager::load_so_proxy();

    // dynamic plugins
    if ( !paths.empty() )
        ::load_plugins(paths);

    // script plugins
    // FIXIT-L need path to script for --list-plugins
    load_list(ScriptManager::get_plugins());

    add_plugins();
}

void PluginManager::reload_so_plugins(const char* paths, SnortConfig* sc)
{
    sc->plugins = new Plugins;
    sc->plugins->plug_map = s_plugins.plug_map;
    if ( paths )
    {
        // once plugin_path is provided for reload, old so_rules will be dropped
        for( auto i = sc->plugins->plug_map.begin(); i != sc->plugins->plug_map.end(); )
        {
            if ( plugin_is_reloadable(i->second.api) )
                i = sc->plugins->plug_map.erase(i);
            else
                ++i;
        }
        ::load_plugins(paths, sc);
    }
    load_so_plugins(sc, true);
}

void PluginManager::reload_so_plugins_cleanup(SnortConfig* sc)
{
    if ( !sc->plugins )
        return;

    // set the new plugins to current
    s_plugins.plug_map.clear();
    s_plugins.plug_map = sc->plugins->plug_map;
    sc->plugins->plug_map.clear();
}

void PluginManager::load_so_plugins(SnortConfig* sc, bool is_reload)
{
    auto p = is_reload ? sc->plugins->plug_map : s_plugins.plug_map;
    for ( auto it = p.begin(); it != p.end(); ++it )
        if ( it->second.api->type == PT_SO_RULE )
            SoManager::add_plugin((const SoApi*)it->second.api, sc, it->second.handle);
}

void PluginManager::list_plugins()
{
    for ( auto it = s_plugins.plug_map.begin(); it != s_plugins.plug_map.end(); ++it )
    {
        Plugin& p = it->second;
        cout << Markup::item();
        cout << p.key;
        cout << " v" << p.api->version;
        cout << " " << p.source;
        cout << endl;
    }
}

void PluginManager::show_plugins()
{
    for ( auto it = s_plugins.plug_map.begin(); it != s_plugins.plug_map.end(); ++it )
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
    PolicySelectorManager::dump_plugins();
}

void PluginManager::release_plugins()
{
    EventManager::release_plugins();
    ActionManager::release_plugins();
    InspectorManager::release_plugins();
    IpsManager::release_plugins();
    MpseManager::release_plugins();
    CodecManager::release_plugins();
    ConnectorManager::release_plugins();
    PolicySelectorManager::release_plugins();

    unload_plugins();
}

const BaseApi* PluginManager::get_api(PlugType type, const char* name)
{
    if ( type >= PT_MAX )
        return nullptr;

    string key;
    set_key(key, symbols+type, name);

    auto it = s_plugins.plug_map.find(key);

    if ( it != s_plugins.plug_map.end() )
        return it->second.api;

    return nullptr;
}

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

    case PT_POLICY_SELECTOR:
        PolicySelectorManager::instantiate((const PolicySelectorApi*)api, mod, sc);
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
    for ( auto it = s_plugins.plug_map.begin(); it != s_plugins.plug_map.end(); ++it )
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
