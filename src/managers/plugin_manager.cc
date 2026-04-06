//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include <atomic>
#include <iostream>
#include <mutex>
#include <sstream>

#include "actions/ips_actions.h"
#include "catch/unit_test.h"
#include "codecs/codec_api.h"
#include "connectors/connectors.h"
#include "framework/plugins.h"
#include "framework/lua_api.h"
#include "helpers/directory.h"
#include "helpers/markup.h"
#include "ips_options/ips_options.h"
#include "log/messages.h"
#include "loggers/loggers.h"
#include "main/modules.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "mp_transport/mp_transports.h"
#include "network_inspectors/network_inspectors.h"
#include "policy_selectors/policy_selectors.h"
#include "search_engines/search_engines.h"
#include "service_inspectors/service_inspectors.h"
#include "stream/stream_inspectors.h"
#include "tracer/trace_loader.h"

#include "action_manager.h"
#include "codec_manager.h"
#include "connector_manager.h"
#include "event_manager.h"
#include "inspector_manager.h"
#include "ips_manager.h"
#include "module_manager.h"
#include "mpse_manager.h"
#include "mp_transport_manager.h"
#include "plug_interface.h"
#include "policy_selector_manager.h"
#include "script_manager.h"
#include "so_manager.h"
#include "trace_logger_manager.h"

using namespace snort;
using namespace std;

struct Symbol
{
    const char* type;
    unsigned version;
    unsigned size;
};

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
    { "mp_transport", MP_TRANSPORT_API_VERSION, sizeof(MPTransportApi) },
    { "trace", TRACE_LOGAPI_VERSION, sizeof(TraceLogApi) }
};

struct CompStr
{
   bool operator()(char const* a, char const* b) const
   { return std::strcmp(a, b) < 0; }
};

struct PlugContextWrapper
{
    PlugContext* context;

    ~PlugContextWrapper()
    { delete context; }
};

using PlugContextPtr = std::shared_ptr<PlugContextWrapper>;

using PluginMap = std::map<const char*, PluginPtr, CompStr>;
using ContextMap = std::map<const char*, PlugContextPtr, CompStr>;

struct PlugSet
{
    PluginMap plug_map;
    ContextMap user_map;
};

// load_set is only set in the main thread which enables reverting in the
// main thread to support delete of prior conf w/o affecting other threads.
static THREAD_LOCAL PlugSet* load_set = nullptr;

static std::atomic<unsigned> load_id = 1;

static std::mutex trash_mutex;
static std::vector<void*> trash;

static const char* current_plugin = nullptr;
static bool close_all_libs = false;

void PluginManager::set_close_all_plugins(bool b)
{ close_all_libs = b; }

static bool do_dlclose()
{
    return !Snort::is_exiting() or close_all_libs;
}

void Plugin::setup(const char* t, const char* s, void* h, const BaseApi* b)
{
    type = t;
    source = s;
    handle = h;
    api = b;
}

Plugin::~Plugin()
{
    if ( !api )
        delete mod;

    else
    {
        if ( api->mod_dtor )
            api->mod_dtor(mod);
    }

#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)
    if ( !catch_enabled() )
#endif
    {
        if ( pin )
            pin->global_term();
    }

    delete pin;
    delete luapi;

    if ( !handle )
        return;

    else if ( in_main_thread() and do_dlclose() )
        dlclose(handle);

    else
    {
        std::lock_guard<std::mutex> lock(trash_mutex);
        trash.push_back(handle);
    }
}

const char* Plugin::get_name()
{ return mod ? mod->get_name() : api->name; }

const char* Plugin::get_help()
{ return mod ? mod->get_help() : api->help; }

//-------------------------------------------------------------------------
// internal methods
//-------------------------------------------------------------------------

// plugins are linked when loaded (RTLD_NOW) so missing symbols
// don't make it this far.  we therefore only need to check
// that shared structs are defined identically, so opts strings
// must be identical.
static bool compatible_builds(const char* plug_opts)
{
    const char* snort_opts = API_OPTIONS;
    assert(snort_opts);

    if ( !plug_opts )
        return false;

    if ( strcmp(snort_opts, plug_opts) )
        return false;

    return true;
}

static bool plugin_is_reloadable(const BaseApi* api)
{
    if ( api->type == PT_SO_RULE )
        return true;

    if ( api->features & PLUGIN_SO_RELOAD )
        return true;

    return false;
}

static bool register_plugin(
    const BaseApi* api, void* handle, const char* file, bool reload)
{
    if ( api->type >= PT_MAX )
    {
        ParseWarning(WARN_PLUGINS, "%s: invalid plugin type: %u", file, (unsigned)api->type);
        return false;
    }

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

    if ( reload and !plugin_is_reloadable(api) )
        return false;

    PluginPtr p = nullptr;
    auto it = load_set->plug_map.find(api->name);

    if ( it != load_set->plug_map.end() )
        p = it->second;

    if ( p )
    {
        if ( p->api->version > api->version )
            return false;  // keep the old one
    }

    if ( !p )
    {
        p = std::make_shared<Plugin>();
        (load_set->plug_map)[api->name] = p;
    }

    p->setup(sym->type, file, handle, api);

    return true;
}

static void load_apis(
    const BaseApi** api, void* handle = nullptr, const char* file = "static", bool reload = false)
{
    unsigned c = 0;

    while ( *api )
    {
        register_plugin(*api, handle, file, reload);
        ++api;

        if ( handle and ++c > 1 )
        {
            // assure we can dlclose on each plugin independently
            // dlclose won't actually close until all plugins in lib are closed
            // coverity[resource_leak]
            dlopen(file, RTLD_NOW|RTLD_LOCAL);
        }
    }
}

static bool load_lib(const char* file, bool reload)
{
    void* handle;

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
    load_apis(api, handle, file, reload);
    return true;
}

static void add_plugin(PluginPtr& p)
{
    if ( !p->api )
        return;

    switch ( p->api->type )
    {
    case PT_IPS_ACTION:
        p->pin = ActionManager::get_interface((const ActionApi*)p->api);
        break;

    case PT_IPS_OPTION:
        p->pin = IpsManager::get_interface((const IpsApi*)p->api);
        break;

    case PT_SEARCH_ENGINE:
        p->pin = MpseManager::get_interface((const MpseApi*)p->api);
        break;

    case PT_LOGGER:
        p->pin = EventManager::get_interface((const LogApi*)p->api);
        break;

    case PT_CONNECTOR:
        p->pin = ConnectorManager::get_interface((const ConnectorApi*)p->api);
        break;

    case PT_POLICY_SELECTOR:
        p->pin = PolicySelectorManager::get_interface((const PolicySelectorApi*)p->api);
        break;

    case PT_CODEC:
        p->pin = CodecManager::get_interface((const CodecApi*)p->api);
        break;

    case PT_SO_RULE:
        p->pin = SoManager::get_interface((const SoApi*)p->api);
        break;

    case PT_INSPECTOR:
        // probes must always be global. they run regardless of selected policy.
        assert( (p->mod && ((const InspectApi*)p->api)->type == IT_PROBE) ?
                p->mod->get_usage() == Module::GLOBAL : true );

        p->pin = InspectorManager::get_interface((const InspectApi*)p->api);
        break;
    
    case PT_MP_TRANSPORT:
        p->pin = MPTransportManager::get_interface((const MPTransportApi*)p->api);
        break;
    
    case PT_TRACE:
        p->pin = TraceLoggerManager::get_interface((const TraceLogApi*)p->api);
        break;

    // LCOV_EXCL_START
    case PT_MAX:
        assert(false);
    // LCOV_EXCL_STOP
    }
#if defined(UNIT_TEST) || defined(BENCHMARK_TEST)
    if ( !catch_enabled() )
#endif
        p->pin->global_init();
}

static void load_libraries(const std::string& paths, bool reload = false)
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
        {
            ParseWarning(WARN_PLUGINS, "%s: can't get file status", path.c_str());
            continue;
        }
        if ( sb.st_mode & S_IFDIR )
        {
            Directory d(path.c_str(), "*.so");

            while ( const char* f = d.next() )
                load_lib(f, reload);
        }
        else if ( sb.st_mode & S_IFREG )
        {
            if ( path.find("/") == string::npos )
                path = "./" + path;

            load_lib(path.c_str(), reload);
        }
        else
            ParseWarning(WARN_PLUGINS, "%s: not a directory or regular file", path.c_str());
    }
}

static void set_module(PluginPtr& p)
{
    if ( p->mod )
        return;

    if ( !p->api or !p->api->mod_ctor )
        return;

    p->mod = p->api->mod_ctor();

    if ( strcmp(p->api->name, p->mod->get_name()) )
    {
        ParseWarning(WARN_PLUGINS, "plugin name %s differs from module name %s, undefined behavior",
            p->api->name, p->mod->get_name());
    }
    else
        ModuleManager::add_module(p->mod);
}

static void add_plugin_modules()
{
    for ( auto& it : load_set->plug_map )
    {
        if ( !it.second->pin )
            continue;

        set_module(it.second);
    }
}

static void init_contexts()
{
    for ( auto& it : load_set->plug_map )
    {
        bool set_context = false;

        if ( !it.second->pin )
        {
            add_plugin(it.second);
            set_context = true;
        }

        if ( !it.second->pin or !set_context )
            continue;

        if ( auto* c = it.second->pin->get_context() )
        {
            PlugContextPtr p = std::make_shared<PlugContextWrapper>();
            p->context = c;
            load_set->user_map.emplace(it.second->get_name(), p);
        }
    }
}

//-------------------------------------------------------------------------
// non-map methods
//-------------------------------------------------------------------------

void PluginManager::empty_trash()
{
    if ( !do_dlclose() )
        return;

    std::lock_guard<std::mutex> lock(trash_mutex);

    if ( trash.empty() )
        return;

    else
    {
        for ( auto h : trash )
            dlclose(h);
    }
    trash.clear();
}

const char* PluginManager::get_current_plugin()
{ return current_plugin; }

PlugType PluginManager::get_type(const char* s)
{
    for ( int i = 0; i < PT_MAX; i++ )
        if ( !strcmp(s, symbols[i].type) )
            return (PlugType)i;

    return PT_MAX;
}

const char* PluginManager::get_type_name(PlugType pt)
{
    assert(pt < PT_MAX);
    return symbols[pt].type;
}

static void dump(const char* label, PlugType pt)
{
    auto dump1 = [](const BaseApi* api, void* pv)
    {
        Dumper* d = (Dumper*)pv;
        d->dump(api->name, api->version);
    };
    Dumper d(label);
    PluginManager::for_each(pt, dump1, (void*)&d);
}

void PluginManager::dump_plugins()
{
    dump("Codecs", PT_CODEC);
    dump("Inspectors", PT_INSPECTOR);
    dump("Search Engines", PT_SEARCH_ENGINE);
    dump("IPS Options", PT_IPS_OPTION);
    dump("SO Rules", PT_SO_RULE);
    dump("IPS Actions", PT_IPS_ACTION);
    dump("Loggers", PT_LOGGER);
    dump("Connectors", PT_CONNECTOR);
    dump("Selectors", PT_POLICY_SELECTOR);
    dump("MP Transports", PT_MP_TRANSPORT);
    dump("Tracers", PT_TRACE);
}

void PluginManager::release_plugins()
{
    EventManager::release_plugins();
    InspectorManager::release_plugins();

    delete load_set;
    empty_trash();
}

void PluginManager::release_plugins(PlugSet* ps)
{
    delete ps;
}

void PluginManager::instantiate(Module* mod, SnortConfig* sc, const char* name)
{
    PlugInterface* pin = get_interface(mod->get_name());

    if ( pin )
    {
        pin->instantiate(mod, sc, name);

        if ( !pin->instantiated )
            pin->instantiated = load_id;
    }
}

void PluginManager::set_instantiated(const char* name)
{
    PlugInterface* pin = get_interface(name);

    if ( pin and !pin->instantiated )
        pin->instantiated = load_id;
}

//-------------------------------------------------------------------------
// 
//-------------------------------------------------------------------------

void PluginManager::init()
{
    assert(!load_set);
    load_set = new PlugSet;
    add_independent_modules();
}

void PluginManager::load_plugins(const BaseApi** lp)
{
    // builtins
    load_apis(lp);
}

void PluginManager::load_plugins(const std::string& paths)
{
    // static plugins
    load_actions();
    load_codecs();
    load_connectors();
    load_ips_options();
    load_loggers();
    load_mp_transports();
    load_search_engines();
    load_policy_selectors();
    load_stream_inspectors();
    load_network_inspectors();
    load_service_inspectors();
    load_trace_loggers();

    // dynamic plugins
    if ( !paths.empty() )
        load_libraries(paths);

    init_contexts();
    add_plugin_modules();
    add_dependent_modules();
}

void PluginManager::load_plugin(const snort::BaseApi* api, LuaApi* luapi, const char* file)
{
    if ( !register_plugin(api, nullptr, file, false) )
        return;

    auto it = load_set->plug_map.find(api->name);
    assert(it != load_set->plug_map.end());

    it->second->luapi = luapi;
    add_plugin(it->second);

    current_plugin = api->name;
    set_module(it->second);
    current_plugin = nullptr;
}

void PluginManager::set_plugins(PlugSet* ps)
{
    assert(!load_set);
    load_set = ps;
}

void PluginManager::clear_plugins()
{
    assert(load_set);
    load_set = nullptr;
}

static PlugSet* get_plug_set()
{
    PlugSet* ps = (load_set ? load_set : SnortConfig::get_conf()->plug_set);
    assert(ps);
    return ps;
}

static PluginMap& get_plug_map(const snort::SnortConfig* sc = nullptr)
{
    if ( sc )
        return sc->plug_set->plug_map;

    if ( load_set )
        return load_set->plug_map;

    if ( SnortConfig::get_conf() )
        return SnortConfig::get_conf()->plug_set->plug_map;

    static PlugSet dummy;  // required for empty / local SnortConfig
    return dummy.plug_map;
}

void PluginManager::reload_plugins(const char* paths, bool)
{
    assert(!load_set);
    InspectorManager::update_map();
    const PlugSet* curr = get_plug_set();

    load_set = new PlugSet;
    load_set->plug_map = curr->plug_map;

    if ( !paths )
    {
        load_set->user_map = curr->user_map;
        ++load_id;
        return;
    }

    for ( auto it = load_set->plug_map.begin(); it != load_set->plug_map.end(); )
    {
        if ( it->second->handle and plugin_is_reloadable(it->second->api) )
        {
            it = load_set->plug_map.erase(it);
        }
        else
        {
            const char* name = it->second->get_name();
            auto ic = curr->user_map.find(name);

            if ( ic != curr->user_map.end() )
                load_set->user_map[name] = ic->second;

            ++it;
        }
    }

    std::string spath = paths;
    load_libraries(spath, true);

    ++load_id;

    init_contexts();
    add_plugin_modules();
}

void PluginManager::unload_plugins()
{
    delete load_set;
    load_set = nullptr;
}

void PluginManager::capture_plugins(SnortConfig* sc)
{
    sc->plug_set = load_set;
    load_set = nullptr;
}

void PluginManager::revert_plugins(SnortConfig* sc)
{
    if ( !sc->plug_set )
        return;

    assert(!load_set);
    load_set = sc->plug_set;
    sc->plug_set = nullptr;
}

void PluginManager::thread_init()
{
    const PluginMap& plug_map = get_plug_map();

    for ( const auto& it : plug_map )
    {
        if ( it.second->pin and it.second->pin->instantiated > 0 )
            it.second->pin->thread_init();
    }
}

void PluginManager::thread_reinit(const SnortConfig* sc)
{
    const PluginMap& plug_map = get_plug_map();

    for ( const auto& it : plug_map )
    {
        if ( it.second->pin and it.second->pin->instantiated == load_id )
            it.second->pin->thread_init();
    }

    get_default_network_policy(sc)->cd_mgr->thread_reinit();

    ConnectorManager::thread_reinit();
    EventManager::reload_outputs();
    InspectorManager::thread_reinit(sc);
}

void PluginManager::thread_term(bool trace)
{
    const PluginMap& plug_map = get_plug_map();

    for ( const auto& it : plug_map )
    {
        if ( it.second->pin and it.second->pin->instantiated > 0 )
        {
            if ( (trace and it.second->api->type != PT_TRACE) or
                (!trace and it.second->api->type == PT_TRACE) )
            {
                continue;
            }
            it.second->pin->thread_term();
        }
    }
}

using PlugList = std::vector<PluginPtr>;

static PlugList get_plug_list()
{
    const PluginMap& plug_map = get_plug_map();
    PlugList pl;

    for ( const auto& it : plug_map )
    {
        if ( it.second->api )
            pl.push_back(it.second);
    }
    std::sort(pl.begin(), pl.end(),
        [] (const PluginPtr& a, const PluginPtr& b)
        { return !strcmp(a->type, b->type) ? strcmp(a->api->name, b->api->name) < 0 : strcmp(a->type, b->type) < 0; });

    return pl;
}

void PluginManager::list_plugins(const char* s)
{
    PlugList pl = get_plug_list();

    for ( const auto& p : pl )
    {
        if ( s and *s and strcmp(s, p->type) )
            continue;

        cout << Markup::item();
        cout << p->type << "::" << p->api->name;
        cout << " v" << p->api->version;
        cout << " " << p->source;
        cout << endl;
    }
}

void PluginManager::show_plugins(const char* s)
{
    PlugList pl = get_plug_list();

    for ( const auto& p : pl )
    {
        if ( s and *s and strcmp(s, p->type) )
            continue;

        cout << Markup::item();
        cout << Markup::emphasis_on();
        cout << p->type << "::" << p->get_name();
        cout << Markup::emphasis_off();
        cout << ": " << p->get_help() << endl;
    }
}

//-------------------------------------------------------------------------
// 
//-------------------------------------------------------------------------

const char* PluginManager::get_available_plugins(PlugType type, const char* prefix)
{
    static std::string s;
    s.clear();

    if ( prefix )
        s = prefix;

    const PluginMap& plug_map = get_plug_map();

    for ( const auto& it : plug_map )
    {
        const auto* api = it.second->api;

        if ( !api or type != api->type )
            continue;

        if ( !s.empty() )
            s += " | ";

        s += api->name;
    }
    return s.c_str();
}

PluginPtr PluginManager::get_plugin(const char* name)
{
    const PluginMap& plug_map = get_plug_map();
    auto it = plug_map.find(name);

    return (it == plug_map.end()) ? nullptr : it->second;
}

const BaseApi* PluginManager::get_api(const char* name)
{
    PluginPtr p = get_plugin(name);
    return p ? p->api : nullptr;
}

PlugContext* PluginManager::get_context(const char* name)
{
    PlugSet* ps = get_plug_set();
    auto it = ps->user_map.find(name);

    return (it == ps->user_map.end()) ? nullptr : it->second->context;
}

PlugInterface* PluginManager::get_interface(const char* name)
{
    PluginPtr p = get_plugin(name);
    return p ? p->pin : nullptr;
}

std::vector<PlugInterface*> PluginManager::get_interfaces(PlugType pt)
{
    std::vector<PlugInterface*> piv;
    const PluginMap& plug_map = get_plug_map();

    for ( const auto& it : plug_map )
    {
        if ( !it.second->api )
            continue;

        if ( it.second->api->type == pt )
            piv.push_back(it.second->pin);
    }
    return piv;
}

unsigned PluginManager::for_each(PlugType pt, BaseFunc pf, void* pv)
{
    const PluginMap& plug_map = get_plug_map();
    unsigned c = 0;

    for ( const auto& it : plug_map )
    {
        if ( !it.second->api )
            continue;

        if ( it.second->api->type == pt )
        {
            pf(it.second->api, pv);
            c++;
        }
    }
    return c;
}

unsigned PluginManager::for_each(PlugType pt, PlugFunc pf, void* pv)
{
    const PluginMap& plug_map = get_plug_map();
    unsigned c = 0;

    for ( const auto& it : plug_map )
    {
        if ( !it.second->api )
            continue;

        if ( it.second->api->type == pt )
        {
            pf(it.second->pin, pv);
            c++;
        }
    }
    return c;
}

//-------------------------------------------------------------------------
// module only methods
//-------------------------------------------------------------------------

void PluginManager::add_module(Module* m)
{
#ifdef REG_TEST
    PlugSet* ps = get_plug_set();
#else
    PlugSet* ps = load_set;
#endif
    assert(ps);
    assert(ps->plug_map.find(m->get_name()) == ps->plug_map.end());

    PluginPtr p = std::make_shared<Plugin>();
    (ps->plug_map)[m->get_name()] = p;

    p->type = "basic";
    p->mod = m;

    ModuleManager::add_module(m);
}

Module* PluginManager::get_module(const char* s, const snort::BaseApi*& a)
{
    PluginPtr p = get_plugin(s);

    if ( !p )
        return nullptr;

    a = p->api;
    return p->mod;
}

Module* PluginManager::get_module(const char* s)
{
    const BaseApi* api;
    return get_module(s, api);
}

std::list<Module*> PluginManager::get_all_modules(const snort::SnortConfig* sc)
{
    const PluginMap& plug_map = get_plug_map(sc);
    std::list<Module*> mods;

    for ( const auto& it : plug_map )
    {
        if ( it.second->mod )
            mods.push_back(it.second->mod);
    }
    return mods;
}

