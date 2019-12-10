//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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
// module_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "module_manager.h"

#include <libgen.h>
#include <lua.hpp>

#include <algorithm>
#include <cassert>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "framework/base_api.h"
#include "framework/module.h"
#include "helpers/markup.h"
#include "log/messages.h"
#include "main/modules.h"
#include "main/shell.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"
#include "parser/vars.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#include "plugin_manager.h"

// "Lua" includes
#include "lua_bootstrap.h"
#include "lua_coreinit.h"

using namespace snort;
using namespace std;

struct ModHook
{
    Module* mod;
    const BaseApi* api;
    luaL_Reg* reg;

    ModHook(Module*, const BaseApi*);
    ~ModHook();

    void init();
};

static std::unordered_map<std::string, ModHook*> s_modules;
static std::unordered_map<std::string, const Parameter*> s_pmap;

static unsigned s_errors = 0;

std::set<uint32_t> ModuleManager::gids;

static string s_current;
static string s_name;
static string s_type;

// for callbacks from Lua
static SnortConfig* s_config = nullptr;

static std::mutex stats_mutex;

// forward decls
extern "C"
{
    bool open_table(const char*, int);
    void close_table(const char*, int);

    bool set_bool(const char* fqn, bool val);
    bool set_number(const char* fqn, double val);
    bool set_string(const char* fqn, const char* val);
    bool set_alias(const char* from, const char* to);

    const char* push_include_path(const char* file);
    void pop_include_path();
}

//-------------------------------------------------------------------------
// boot foo
//-------------------------------------------------------------------------

const char* ModuleManager::get_lua_bootstrap()
{ return lua_bootstrap; }

const char* ModuleManager::get_lua_coreinit()
{ return lua_coreinit; }

//-------------------------------------------------------------------------
// ModHook foo
//-------------------------------------------------------------------------

ModHook::ModHook(Module* m, const BaseApi* b)
{
    mod = m;
    api = b;
    reg = nullptr;
    init();
}

ModHook::~ModHook()
{
    if ( reg )
        delete[] reg;

    if ( api && api->mod_dtor )
        api->mod_dtor(mod);
    else
        delete mod;
}

void ModHook::init()
{
    const Command* c = mod->get_commands();

    if ( !c )
        return;

    unsigned n = 0;
    while ( c[n].name )
        n++;

    // constructing reg here may seem like overkill
    // ... why not just typedef Command to luaL_Reg?
    // because the help would not be supplied or it
    // would be out of date, out of sync, etc. QED
    reg = new luaL_Reg[++n];
    unsigned k = 0;

    while ( k < n )
    {
        reg[k].name = c[k].name;
        reg[k].func = c[k].func;
        k++;
    }
}

//-------------------------------------------------------------------------
// helper functions
//-------------------------------------------------------------------------

static void set_type(string& fqn)
{
    if ( s_type.empty() )
        return;

    size_t pos = fqn.find_first_of('.');

    if ( pos == fqn.npos )
        pos = fqn.size();

    fqn.replace(0, pos, s_type);
}

static void set_top(string& fqn)
{
    size_t pos = fqn.find_first_of('.');

    if ( pos != fqn.npos )
        fqn.erase(pos);
}

static void trace(const char* s, const char* fqn, Value& v)
{
#if 1
    if ( s )
        return;
#endif

    if ( v.get_type() == Value::VT_STR )
        printf("%s: %s = '%s'\n", s, fqn, v.get_string());
    else
        printf("%s: %s = " STDi64 "\n", s, fqn, v.get_int64());
}

static ModHook* get_hook(const char* s)
{
    auto mh = s_modules.find(s);
    if ( mh != s_modules.end() )
        return mh->second;

    return nullptr;
}

//-------------------------------------------------------------------------
// dump methods:
// recurse over parameters and output like this:
// int snort_target_based.max_attribute_hosts = 0: maximum number of hosts
// in attribute table { 32:207551 }
// (type, fqn, default, brief help, range)
//-------------------------------------------------------------------------

enum DumpFormat { DF_STD, DF_TAB, DF_LUA };
static DumpFormat dump_fmt = DF_STD;

static void dump_field_std(const string& key, const Parameter* p)
{
    cout << Markup::item();
    cout << p->get_type();
    cout << " " << Markup::emphasis(Markup::escape(key));

    if ( p->deflt )
        cout << " = " << p->deflt;

    cout << ": " << p->help;

    if ( const char* r = p->get_range() )
        cout << " { " << r << " }";

    cout << endl;
}

static void dump_field_tab(const string& key, const Parameter* p)
{
    cout << Markup::item();
    cout << p->get_type();
    cout << "\t" << Markup::emphasis(Markup::escape(key));

    if ( p->deflt )
        cout << "\t" << p->deflt;
    else
        cout << "\t";

    cout << "\t" << p->help;

    if ( const char* r = p->get_range() )
        cout << "\t" << r;
    else
        cout << "\t";

    cout << endl;
}

static void dump_field_lua(const string& key, const Parameter* p, bool table = false)
{
    // implied values (rule keywords) and command line args
    // don't really have defaults, so skip them
    if ( key.find('~') != string::npos ||
        key.find('-') != string::npos ||
        key.find('*') != string::npos )
        return;

    if ( table || p->is_table() )
        cout << key << " = { }";

    // if there is no default, emit nothing
    else if ( !p->deflt )
        return;

    else if ( p->is_quoted() )
    {
        const char* s = p->deflt ? p->deflt : " ";
        cout << key << " = '" << s << "'";
    }
    else
    {
        const char* s = p->deflt ? p->deflt : "0";
        cout << key << " = " << s;
    }

    cout << endl;
}

static void dump_table(string&, const char* pfx, const Parameter*, bool list = false);

static void dump_field(string& key, const char* pfx, const Parameter* p, bool list = false)
{
    unsigned n = key.size();

    if ( list || !p->name )
        key += (dump_fmt == DF_LUA) ? "[1]" : "[]";

    if ( p->name )
    {
        if ( n )
            key += ".";
        key += p->name;
    }

    if ( pfx && strncmp(key.c_str(), pfx, strlen(pfx)) )
    {
        key.erase();
        return;
    }
    // we dump just one list entry
    if ( p->type == Parameter::PT_TABLE )
        dump_table(key, pfx, (const Parameter*)p->range);

    else if ( p->type == Parameter::PT_LIST )
        dump_table(key, pfx, (const Parameter*)p->range, true);

    else
    {
        if ( dump_fmt == DF_LUA )
            dump_field_lua(key, p);

        else if ( dump_fmt == DF_TAB )
            dump_field_tab(key, p);

        else
            dump_field_std(key, p);
    }
    key.erase(n);
}

static void dump_table(string& key, const char* pfx, const Parameter* p, bool list)
{
    if ( dump_fmt == DF_LUA )
    {
        dump_field_lua(key, p, true);

        if ( list )
        {
            string fqn = key + "[1]";
            dump_field_lua(fqn, p, true);
        }
    }
    while ( p && p->name )
        dump_field(key, pfx, p++, list);
}

//-------------------------------------------------------------------------
// set methods
//-------------------------------------------------------------------------

static const Parameter* get_params(
    const string& sfx, Module* m, const Parameter* p, int idx = 1)
{
    size_t pos = sfx.find_first_of('.');
    std::string new_fqn;

    if ( pos == string::npos )
    {
        if ( p[0].name && !p[1].name )
            return p;
        else
            new_fqn = sfx;
    }
    else
    {
        new_fqn = sfx.substr(pos + 1);
    }

    string name = new_fqn.substr(0, new_fqn.find_first_of('.'));

    while ( p->name )
    {
        if ( *p->name == '$' and m->matches(p->name, name) )
            break;

        else if ( name == p->name )
            break;

        ++p;
    }

    if ( !p->name )
        return nullptr;

    if ( p->type != Parameter::PT_TABLE &&
        p->type != Parameter::PT_LIST )
        return p;

    if ( new_fqn.find_first_of('.') == std::string::npos )
    {
        if ( idx && p->type == Parameter::PT_LIST )
        {
            const Parameter* tmp_p =
                reinterpret_cast<const Parameter*>(p->range);

            // FIXIT-L this will fail if we are opening a a list with only one Parameter
            if ( tmp_p[0].name && !tmp_p[1].name )
                return tmp_p;
        }
        return p;
    }

    p = (const Parameter*)p->range;
    return get_params(new_fqn, m, p, idx);
}

// FIXIT-M vars may have been defined on command line. that mechanism will
// be replaced with pulling a Lua chunk from the command line and stuffing
// into L before setting configs; that will overwrite
//
// FIXIT-M should only need one table with dynamically typed vars
//
//
// FIXIT-M this is a hack to tell vars by naming convention; with one table
// this is obviated but if multiple tables are kept might want to change
// these to a module with parameters
//
// FIXIT-L presently no way to catch errors like EXTERNAL_NET = not HOME_NET
// which becomes a bool var and is ignored.
static bool set_var(const char* fqn, Value& val)
{
    if ( val.get_type() != Value::VT_STR )
        return false;

    if ( get_ips_policy() == nullptr )
        return true;

    trace("var", fqn, val);
    const char* s = val.get_string();

    if ( strstr(fqn, "PATH") )
        AddVarToTable(s_config, fqn, s);

    else if ( strstr(fqn, "PORT") )
        PortVarDefine(s_config, fqn, s);

    else if ( strstr(fqn, "NET") || strstr(fqn, "SERVER") )
        ParseIpVar(s_config, fqn, s);

    return true;
}

static bool set_param(Module* mod, const char* fqn, Value& val)
{
    if ( !mod->verified_set(fqn, val, s_config) )
    {
        ParseError("%s is invalid", fqn);
        ++s_errors;
    }

    trace("par", fqn, val);
    return true;
}

static bool ignored(const char* fqn)
{
    static const char* ignore = nullptr;

    if ( !ignore )
    {
        ignore = getenv("SNORT_IGNORE");
        if ( !ignore )
            ignore = "";
    }
    const char* s = strstr(ignore, fqn);

    if ( !s )
        return false;

    if ( s != ignore && s[-1] != ' ' )
        return false;

    s += strlen(fqn);

    if ( *s && *s != ' ' )
        return false;

    return true;
}

static bool set_value(const char* fqn, Value& v)
{
    string t = fqn;
    set_type(t);
    fqn = t.c_str();

    string key = t;
    set_top(key);

    Module* mod = ModuleManager::get_module(key.c_str());

    if ( !mod )
    {
        bool found = set_var(fqn, v);

        if ( !found && !ignored(fqn) )
            ParseWarning(WARN_SYMBOLS, "unknown symbol %s", fqn);
        return found;
    }

    const Parameter* p;
    auto a = s_pmap.find(t);

    if ( a != s_pmap.end() )
        p = a->second;

    else
    {
        // now we must traverse the mod params to get the leaf
        string s = fqn;
        p = get_params(s, mod, mod->get_parameters());

        if ( !p )
            p = get_params(s, mod, mod->get_default_parameters());
    }

    if ( !p )
    {
        // FIXIT-L handle things like x = { 1 } where x is a table not a
        // list and 1 should be considered a key not a value; ideally say
        // can't find x.1 instead of just can't find x
        ParseError("can't find %s", fqn);
        ++s_errors;
        return false;
    }

    if ( p->validate(v) )
    {
        v.set(p);
        set_param(mod, fqn, v);
        return true;
    }

    if ( v.get_type() == Value::VT_STR )
        ParseError("invalid %s = '%s'", fqn, v.get_string());
    else if ( v.get_real() == v.get_int64() )
        ParseError("invalid %s = " STDi64, fqn, v.get_int64());
    else
        ParseError("invalid %s = %g", fqn, v.get_real());

    ++s_errors;
    return false;
}

//-------------------------------------------------------------------------
// defaults - set all parameter table defaults for each configured module
// but there are no internal default list or list items.  since Lua calls
// open table for each explicitly configured table only, here is what we
// do:
//
// -- on open_table(), call Module::begin() for each module, list, and list
//    item
// -- recursively set all defaults after calling Module::begin(), skipping
//    lists and list items
// -- on close_table(), call Module::end() for each module, list, and list
//    item
//-------------------------------------------------------------------------

static bool top_level(const char* s)
{ return !strchr(s, '.'); }

static bool begin(Module* m, const Parameter* p, const char* s, int idx, int depth)
{
    // Module::(verified_)begin() will be called for top-level tables, lists, and list items only
    if ( top_level(s) )
    {
        if ( !m->verified_begin(s, idx, s_config) )
            return false;
        // don't set list defaults
        if ( m->is_list() and !idx )
            return true;
        if ( !p )
        {
            p = m->get_parameters();
            assert(p);
        }
    }
    else
    {
        assert(p);
        if ( (!idx and p->type == Parameter::PT_LIST) or
             (idx and p->type != Parameter::PT_LIST) )
        {
            if ( !m->verified_begin(s, idx, s_config) )
                return false;
        }
        if ( p->type == Parameter::PT_LIST )
        {
            // don't set list defaults (list items have idx > 0)
            if ( !idx )
                return true;

            // set list item defaults only if explicitly configured
            // (this is why it is done here and not in the loop below)
            const Parameter* list_item_params = reinterpret_cast<const Parameter*>(p->range);

            return begin(m, list_item_params, s, idx, depth+1);
        }
    }

    // don't begin subtables again
    if ( !top_level(s) && !depth )
        return true;

    while ( p->name )
    {
        string fqn = s;
        fqn += '.';
        fqn += p->name;

        switch ( p->type )
        {
        // traverse subtables only to set defaults
        case Parameter::PT_TABLE:
            {
                const Parameter* table_item_params = reinterpret_cast<const Parameter*>(p->range);

                if ( !begin(m, table_item_params, fqn.c_str(), idx, depth+1) )
                    return false;
            }
            break;

        // skip lists, they must be configured explicitly
        case Parameter::PT_LIST:
        case Parameter::PT_MAX:
            break;

        case Parameter::PT_BOOL:
            if ( p->deflt )
            {
                bool b = p->get_bool();
                set_bool(fqn.c_str(), b);
            }
            break;

        case Parameter::PT_INT:
        case Parameter::PT_PORT:
        case Parameter::PT_REAL:
            if ( p->deflt )
            {
                double d = p->get_number();
                set_number(fqn.c_str(), d);
            }
            break;

        // everything else is a string of some sort
        default:
            if ( p->deflt )
                set_string(fqn.c_str(), p->deflt);
            break;
        }
        ++p;
    }
    return true;
}

// no need to recurse here; we only call Module::end() for
// top-level, lists, and list items
static bool end(Module* m, const Parameter* p, const char* s, int idx)
{
    bool top_param = !p;

    if ( !p )
    {
        p = m->get_parameters();
        assert(p);
    }
    // same as begin() but we must include top_param to catch
    // top-level lists
    if ( top_level(s) or
         (top_param and p->type != Parameter::PT_TABLE) or
         (!idx and p->type == Parameter::PT_LIST) or
         (idx and p->type != Parameter::PT_LIST) )
    {
        return m->verified_end(s, idx, s_config);
    }
    return true;
}

static bool interested(Module* m)
{
    if ( m->get_usage() == Module::GLOBAL &&
         only_inspection_policy() && !default_inspection_policy() )
        return false;

    if ( m->get_usage() != Module::INSPECT && only_inspection_policy() )
        return false;

    if ( m->get_usage() != Module::DETECT && only_ips_policy() )
        return false;

    if ( m->get_usage() != Module::CONTEXT && only_network_policy() )
        return false;

    return true;
}

//-------------------------------------------------------------------------
// ffi methods
//-------------------------------------------------------------------------

SO_PUBLIC bool set_alias(const char* from, const char* to)
{
    s_name = from;
    s_type = to;
    return true;
}

SO_PUBLIC bool open_table(const char* s, int idx)
{
    const char* orig = s;
    string fqn = s;
    set_type(fqn);
    s = fqn.c_str();

    string key = fqn;
    set_top(key);

    // ips option parameters only used in rules which
    // are non-lua; may be possible to allow a subtable
    // for lua config of ips option globals
    ModHook* h = get_hook(key.c_str());

    if ( !h || (h->api && h->api->type == PT_IPS_OPTION) )
        return false;

    // FIXIT-M only basic modules, inspectors and ips actions can be reloaded at present
    if ( ( Snort::is_reloading() ) and h->api
            and h->api->type != PT_INSPECTOR and h->api->type != PT_IPS_ACTION )
        return false;

    Module* m = h->mod;
    const Parameter* p = nullptr;

    if ( !interested(m) )
        return false;

    if ( strcmp(m->get_name(), s) )
    {
        std::string sfqn = s;
        p = get_params(sfqn, m, m->get_parameters(), idx);

        if ( !p )
            p = get_params(sfqn, m, m->get_default_parameters(), idx);

        if ( !p )
        {
            ParseError("can't find %s", s);
            return false;
        }
        else if ( (idx > 0) && (p->type == Parameter::PT_TABLE) )
        {
            ParseError("%s is a table; all elements must be named", s);
            return false;
        }
    }

    if ( s_current != key )
    {
        if ( fqn != orig )
            LogMessage("\t%s (%s)\n", key.c_str(), orig);
        else
            LogMessage("\t%s\n", key.c_str());
        s_current = key;
    }

    if ( !begin(m, p, s, idx, 0) )
    {
        ParseError("can't open %s", m->get_name());
        return false;
    }

    return true;
}

SO_PUBLIC void close_table(const char* s, int idx)
{
    string fqn = s;
    set_type(fqn);
    s = fqn.c_str();

    string key = fqn;
    set_top(key);

    const bool top = !idx && key == s;

    if ( ModHook* h = get_hook(key.c_str()) )
    {
        if ( !end(h->mod, nullptr, s, idx) )
            ParseError("can't close %s", h->mod->get_name());

        else if (h->api && top)
        {
            if ( !s_name.empty() )
                PluginManager::instantiate(h->api, h->mod, s_config, s_name.c_str());
            else
                PluginManager::instantiate(h->api, h->mod, s_config);
        }
    }

    if ( top )
    {
        s_name.clear();
        s_type.clear();
    }
}

SO_PUBLIC bool set_bool(const char* fqn, bool b)
{
    Value v(b);
    return set_value(fqn, v);
}

SO_PUBLIC bool set_number(const char* fqn, double d)
{
    Value v(d);
    return set_value(fqn, v);
}

SO_PUBLIC bool set_string(const char* fqn, const char* s)
{
    Value v(s);
    return set_value(fqn, v);
}

SO_PUBLIC const char* push_include_path(const char* file)
{
    static std::string path;
    path = "";
    const char* code = get_config_file(file, path);
    push_parse_location(code, path.c_str(), file);
    return path.c_str();
}

SO_PUBLIC void pop_include_path()
{
    pop_parse_location();
}

//-------------------------------------------------------------------------
// private methods
//-------------------------------------------------------------------------

static bool comp_mods(const ModHook* l, const ModHook* r)
{
    const Module* lm = l->mod;
    const Module* rm = r->mod;
    return strcmp(lm->get_name(), rm->get_name()) < 0;
}

static bool comp_gids(const ModHook* l, const ModHook* r)
{
    const Module* lm = l->mod;
    const Module* rm = r->mod;

    if ( lm->get_gid() == rm->get_gid() )
        return comp_mods(l, r);

    return ( lm->get_gid() < rm->get_gid() );
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

void ModuleManager::init()
{
    module_init();
}

void ModuleManager::term()
{
    for ( auto& mh : s_modules )
        delete mh.second;

    s_modules.clear();
}

void ModuleManager::add_module(Module* m, const BaseApi* b)
{
    ModHook* mh = new ModHook(m, b);

    assert(s_modules.find(mh->mod->get_name()) == s_modules.end());

    s_modules[mh->mod->get_name()] = mh;

    Profiler::register_module(m);

    if ( m->get_gid() )
        gids.emplace(m->get_gid());
}

Module* ModuleManager::get_module(const char* s)
{
    auto mh = s_modules.find(s);
    if ( mh != s_modules.end() )
        return mh->second->mod;

    return nullptr;
}

Module* ModuleManager::get_default_module(const char* s, SnortConfig* sc)
{
    Module* mod = get_module(s);

    if ( mod )
    {
        mod->verified_begin(s, 0, sc);
        mod->verified_end(s, 0, nullptr);
    }
    return mod;
}

list<Module*> ModuleManager::get_all_modules()
{
    list<Module*> ret;

    for ( auto& mh : s_modules )
       ret.emplace_back(mh.second->mod);

    return ret;
}

static list<ModHook*> get_all_modhooks()
{
    list<ModHook*> ret;

    for ( auto& mh : s_modules )
       ret.emplace_back(mh.second);

    return ret;
}

void ModuleManager::set_config(SnortConfig* sc)
{ s_config = sc; }

void ModuleManager::reset_errors()
{ s_errors = 0; }

unsigned ModuleManager::get_errors()
{ return s_errors; }

void ModuleManager::list_modules(const char* s)
{
    PlugType pt = s ? PluginManager::get_type(s) : PT_MAX;
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);
    unsigned c = 0;

    for ( auto* mh : mod_hooks )
    {
        if (
            !s || !*s ||
            (mh->api && mh->api->type == pt) ||
            (!mh->api && !strcmp(s, "basic"))
            )
        {
            LogMessage("%s\n", mh->mod->get_name());
            c++;
        }
    }
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::show_modules()
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);

    for ( auto* mh : mod_hooks )
    {
        const char* t = mh->api ? PluginManager::get_type_name(mh->api->type) : "basic";

        cout << Markup::item();
        cout << Markup::emphasis(mh->mod->get_name());
        cout << " (" << t;
        cout << "): " << mh->mod->get_help();
        cout << endl;
    }
}

void ModuleManager::dump_modules()
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);
    Dumper d("Modules");

    for ( auto* mh : mod_hooks )
        if ( !mh->api )
            d.dump(mh->mod->get_name());
}

static const char* mod_type(const BaseApi* api)
{
    if ( !api )
        return "basic";

    return PluginManager::get_type_name(api->type);
}

static const char* mod_use(Module::Usage use)
{
    switch ( use )
    {
    case Module::GLOBAL : return "global";
    case Module::CONTEXT: return "context";
    case Module::INSPECT: return "inspect";
    case Module::DETECT : return "detect";
    }
    assert(false);
    return "error";
}

void ModuleManager::show_module(const char* name)
{
    if ( !name || !*name )
    {
        cerr << "module name required" << endl;
        return;
    }
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_gids);
    unsigned c = 0;

    for ( auto* mh : mod_hooks )
    {
        const Module* m = mh->mod;
        assert(m);

        if ( strcmp(m->get_name(), name) )
            continue;

        cout << endl << Markup::head(3) << name << endl << endl;

        if ( const char* h = m->get_help() )
            cout << endl << "What: " << h << endl;

        cout << endl << "Type: "  << mod_type(mh->api) << endl;
        cout << endl << "Usage: "  << mod_use(m->get_usage()) << endl;

        const Parameter* params = m->get_parameters();
        const Parameter* def_params = m->get_default_parameters();

        if ( ( params and params->type < Parameter::PT_MAX ) ||
             ( def_params and def_params->type < Parameter::PT_MAX ) )
        {
            cout << endl << "Configuration: " << endl << endl;
            show_configs(name, true);
        }

        if ( m->get_commands() )
        {
            cout << endl << "Commands: " << endl << endl;
            show_commands(name, true);
        }

        if ( m->get_rules() )
        {
            cout << endl << "Rules: " << endl << endl;
            show_rules(name, true);
        }

        if ( m->get_pegs() )
        {
            cout << endl << "Peg counts: " << endl << endl;
            show_pegs(name, true);
        }
        c++;
    }
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::reload_module(const char* name, SnortConfig* sc)
{
    ModHook* h = get_hook(name);

    // FIXIT-L: we can check that h->api is not null here or inside instantiate.
    // Both alternatives prevent crashing in instantiate(). However,
    // checking it here might be too aggressive, because we are also saying it
    // is an error. That makes the caller of this function
    // (get_updated_module()) discard other legitimate reload operations, e.g.
    // the newly read configuration. We should decide on this when proper
    // reload functionality gets implemented.
    if ( h and h->api and h->mod and sc )
    {
        PluginManager::instantiate(h->api, h->mod, sc);
        s_errors += get_parse_errors();
    }
    else
    {
        cout << "Module " << name <<" doesn't exist or reload not implemented.";
        cout << endl;
        ++s_errors;
    }
}

static bool selected(const Module* m, const char* pfx, bool exact)
{
    if ( !pfx )
        return true;

    if ( exact && strcmp(m->get_name(), pfx) )
        return false;

    else if ( !exact && strncmp(m->get_name(), pfx, strlen(pfx)) )
        return false;

    return true;
}

void ModuleManager::show_configs(const char* pfx, bool exact)
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);
    unsigned c = 0;

    for ( auto* mh : mod_hooks )
    {
        Module* m = mh->mod;
        string s;

        if ( !selected(m, pfx, exact) )
            continue;

        if ( m->is_list() )
        {
            s = m->name;

            if ( m->params->name )
                dump_table(s, pfx, m->params, true);
            else
                dump_field(s, pfx, m->params);
        }
        else if ( m->is_table() )
        {
            s = m->name;
            dump_table(s, pfx, m->params);
        }
        else
        {
            dump_field(s, pfx, m->params);
        }

        s = m->name;

        if ( m->default_params )
            dump_table(s, pfx, m->default_params);

        if ( !pfx )
            cout << endl;

        c++;
    }
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::dump_defaults(const char* pfx)
{
    dump_fmt = DF_LUA;
    show_configs(pfx);
}

void ModuleManager::show_commands(const char* pfx, bool exact)
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);
    unsigned n = 0;

    for ( auto* mh : mod_hooks )
    {
        const Module* m = mh->mod;

        if ( !selected(m, pfx, exact) )
            continue;

        const Command* c = m->get_commands();

        if ( !c )
            continue;

        while ( c->name )
        {
            cout << Markup::item();
            cout << Markup::emphasis_on();
            cout << mh->mod->get_name();
            cout << "." << c->name;
            cout << Markup::emphasis_off();
            cout << c->get_arg_list();
            cout << ": " << c->help;
            cout << endl;
            c++;
        }
        n++;
    }
    if ( !n )
        cout << "no match" << endl;
}

bool ModuleManager::gid_in_use(uint32_t gid)
{
    return gids.find(gid) != gids.end();
}

void ModuleManager::show_gids(const char* pfx, bool exact)
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_gids);
    unsigned c = 0;

    for ( auto* mh : mod_hooks )
    {
        const Module* m = mh->mod;
        assert(m);

        if ( !selected(m, pfx, exact) )
            continue;

        unsigned gid = m->get_gid();

        if ( gid )
        {
            cout << Markup::item();
            cout << Markup::emphasis_on();
            cout << gid;
            cout << Markup::emphasis_off();
            cout << ": " << m->get_name();
            cout << endl;
        }
        c++;
    }
    if ( !c )
        cout << "no match" << endl;
}

static const char* peg_op(CountType ct)
{
    switch ( ct )
    {
    case CountType::SUM: return " (sum)";
    case CountType::NOW: return " (now)";
    case CountType::MAX: return " (max)";
    default: break;
    }
    assert(false);
    return "error";
}

void ModuleManager::show_pegs(const char* pfx, bool exact)
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_gids);
    unsigned c = 0;

    for ( auto* mh : mod_hooks )
    {
        const Module* m = mh->mod;
        assert(m);

        if ( !selected(m, pfx, exact) )
            continue;

        const PegInfo* pegs = m->get_pegs();

        if ( !pegs )
            continue;

        while ( pegs->name )
        {
            cout << Markup::item();
            cout << Markup::emphasis_on();
            cout << mh->mod->get_name();
            cout << "." << pegs->name;
            cout << Markup::emphasis_off();
            cout << ": " << pegs->help;
            cout << peg_op(pegs->type);
            cout << endl;
            ++pegs;
        }
        c++;
    }
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::load_commands(Shell* sh)
{
    // FIXIT-L ideally only install commands from configured modules
    // FIXIT-L install commands into working shell
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);

    for ( auto* mh : mod_hooks )
    {
        if ( mh->reg )
            sh->install(mh->mod->get_name(), mh->reg);
    }
}

// move builtin generation to a better home?
// FIXIT-L builtins should allow configurable nets and ports
// FIXIT-L builtins should have accurate proto
//       (but ip winds up in all others)
// FIXIT-L if msg has C escaped embedded quotes, we break
//ss << "alert tcp any any -> any any ( ";
static void make_rule(ostream& os, const Module* m, const RuleMap* r)
{
    os << "alert ( ";
    os << "gid:" << m->get_gid() << "; ";
    os << "sid:" << r->sid << "; ";
    os << "rev:1; priority:3; ";
    os << "msg:\"" << "(" << m->get_name() << ") ";
    os << r->msg << "\"; )";
    os << endl;
}

// FIXIT-L currently no way to know whether a module was activated or not
// so modules with common rules will cause duplicate sid warnings
// eg http_server (old) and http_inspect (new) both have 119:1-34
// only way to avoid that now is to not load plugins with common rules
// (we don't want to suppress it because it could mean something is broken)
void ModuleManager::load_rules(SnortConfig* sc)
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_gids);

    for ( auto* mh : mod_hooks )
    {
        const Module* m = mh->mod;
        const RuleMap* r = m->get_rules();

        if ( !r )
            continue;

        stringstream ss;

        while ( r->msg )
        {
            ss.str("");
            make_rule(ss, m, r);

            // note:  you can NOT do ss.str().c_str() here
            const string& rule = ss.str();
            parse_rules_string(sc, rule.c_str());

            r++;
        }
    }
}

void ModuleManager::dump_stats(SnortConfig*, const char* skip, bool dynamic)
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);

    for ( auto* mh : mod_hooks )
    {
        if ( !skip || !strstr(skip, mh->mod->get_name()) )
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            if ( dynamic )
                mh->mod->show_dynamic_stats();
            else
                mh->mod->show_stats();
        }
    }
}

void ModuleManager::accumulate(SnortConfig*)
{
    auto mod_hooks = get_all_modhooks();

    for ( auto* mh : mod_hooks )
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        mh->mod->prep_counts();
        mh->mod->sum_stats(true);
    }
}

void ModuleManager::accumulate_offload(const char* name)
{
    ModHook* mh = get_hook(name);
    if ( mh )
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        mh->mod->prep_counts();
        mh->mod->sum_stats(true);
    }
}

void ModuleManager::reset_stats(SnortConfig*)
{
    auto mod_hooks = get_all_modhooks();

    for ( auto* mh : mod_hooks )
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        mh->mod->reset_stats();
    }
}

//-------------------------------------------------------------------------
// parameter loading
//-------------------------------------------------------------------------

static void load_table(string&, const Parameter*);

static void load_field(string& key, const Parameter* p)
{
    unsigned n = key.size();

    if ( p->name )
    {
        if ( n )
            key += ".";
        key += p->name;
    }

    if ( p->type == Parameter::PT_TABLE or p->type == Parameter::PT_LIST )
        load_table(key, (const Parameter*)p->range);

    else
        s_pmap[key] = p;

    key.erase(n);
}

static void load_table(string& key, const Parameter* p)
{
    while ( p && p->name )
        load_field(key, p++);
}

void ModuleManager::load_params()
{
    auto mod_hooks = get_all_modhooks();
    mod_hooks.sort(comp_mods);

    for ( auto* mh : mod_hooks )
    {
        Module* m = mh->mod;
        string s;

        if ( m->is_list() )
        {
            s = m->name;

            if ( m->params->name )
                load_table(s, m->params);
            else
                load_field(s, m->params);
        }
        else if ( m->is_table() )
        {
            s = m->name;
            load_table(s, m->params);
        }
        else
        {
            load_field(s, m->params);
        }

        s = m->name;

        if ( m->default_params )
            load_table(s, m->default_params);
    }
}

const Parameter* ModuleManager::get_parameter(const char* table, const char* option)
{
    string key = table;
    key += '.';
    key += option;

    auto a = s_pmap.find(key);

    if (a != s_pmap.end() )
        return a->second;

    return nullptr;
}

//--------------------------------------------------------------------------
// builtin rule outputs
//--------------------------------------------------------------------------

struct RulePtr
{
    const Module* mod;
    const RuleMap* rule;

    RulePtr(const Module* m, const RuleMap* r) : mod(m), rule(r) { }

    bool operator< (RulePtr& rhs) const
    {
        if ( mod->get_gid() != rhs.mod->get_gid() )
            return mod->get_gid() < rhs.mod->get_gid();

         return rule->sid < rhs.rule->sid;
    }
};

static std::vector<RulePtr> get_rules(const char* pfx, bool exact = false)
{
    auto mod_hooks = get_all_modhooks();
    std::vector<RulePtr> rule_set;

    for ( auto* mh : mod_hooks )
    {
        const Module* m = mh->mod;

        if ( !selected(m, pfx, exact) )
            continue;

        const RuleMap* r = m->get_rules();

        if ( !r )
            continue;

        while ( r->msg )
            rule_set.push_back(RulePtr(m, r++));
    }
    std::sort(rule_set.begin(), rule_set.end());
    return rule_set;
}

void ModuleManager::dump_rules(const char* pfx)
{
    std::vector<RulePtr> rule_set = get_rules(pfx);

    for ( auto rp : rule_set )
        make_rule(cout, rp.mod, rp.rule);

    if ( !rule_set.size() )
        cout << "no match" << endl;
}

void ModuleManager::show_rules(const char* pfx, bool exact)
{
    std::vector<RulePtr> rule_set = get_rules(pfx, exact);

    for ( auto rp : rule_set )
    {
        cout << Markup::item();
        cout << Markup::emphasis_on();
        cout << rp.mod->get_gid() << ":" << rp.rule->sid;
        cout << Markup::emphasis_off();
        cout << " (" << rp.mod->get_name() << ")";
        cout << " " << rp.rule->msg;
        cout << endl;
    }
    if ( !rule_set.size() )
        cout << "no match" << endl;
}

void ModuleManager::dump_msg_map(const char* pfx)
{
    std::vector<RulePtr> rule_set = get_rules(pfx);

    for ( auto rp : rule_set )
    {
        cout << rp.mod->get_gid() << " || ";
        cout << rp.rule->sid << " || ";
        cout << rp.mod->get_name() << ": ";
        cout << rp.rule->msg << endl;
    }
    if ( !rule_set.size() )
        cout << "no match" << endl;
}

