/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// module_manager.cc author Russ Combs <rucombs@cisco.com>

#include "module_manager.h"

#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <sstream>
#include <lua.hpp>

#include "shell.h"
#include "framework/base_api.h"
#include "framework/module.h"
#include "managers/plugin_manager.h"
#include "main/snort_config.h"
#include "main/modules.h"
#include "parser/parser.h"
#include "parser/parse_conf.h"
#include "parser/vars.h"
#include "time/profiler.h"
#include "helpers/markup.h"

using namespace std;

struct ModHook
{
    Module* mod;
    const BaseApi* api;
    luaL_reg* reg;

    ModHook(Module*, const BaseApi*);
    ~ModHook();

    void init();
};

typedef list<ModHook*> ModuleList;
static ModuleList s_modules;
static unsigned s_errors = 0;

// for callbacks from Lua
static SnortConfig* s_config = nullptr;

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

    if( !c )
        return;

    unsigned n = 0;
    while ( c[n].name )
        n++;

    // constructing reg here may seem like overkill
    // why not just typedef Command to luaL_reg?
    // because the help would not be supplied or it
    // would be out of data, out of sync, etc. QED
    reg = new luaL_reg[++n];
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
        printf("%s: %s = %lu\n", s, fqn, v.get_long());
}

static ModHook* get_hook(const char* s)
{
    for ( auto p : s_modules )
        if ( !strcmp(p->mod->get_name(), s) )
            return p;

    return nullptr;
}

//-------------------------------------------------------------------------
// dump methods:
// recurse over parameters and output like this:
// int snort_target_based.max_attribute_hosts = 0: maximum number of hosts
// in attribute table { 32:207551 }
// (type, fqn, default, brief help, range)
//-------------------------------------------------------------------------

static void dump_table(string&, const char* pfx, const Parameter*, bool list = false);

static void dump_field(string& key, const char* pfx, const Parameter* p, bool list = false)
{
    unsigned n = key.size();

    if ( list || !p->name )
        key += "[]";

    if ( p->name )
    {
        if ( n )
            key += ".";
        key += p->name;
    }

    // we dump just one list entry
    if ( p->type == Parameter::PT_TABLE )
        dump_table(key, pfx, (Parameter*)p->range);

    else if ( p->type == Parameter::PT_LIST )
        dump_table(key, pfx, (Parameter*)p->range, true);

    else if ( !pfx || !strncmp(key.c_str(), pfx, strlen(pfx)) )
    {
#if 1
        cout << Markup::item();
        cout << p->get_type();
        cout << " " << Markup::emphasis(key);

        if ( p->deflt )
            cout << " = " << (char*)p->deflt;

        cout << ": " << p->help;

        if ( p->range )
            cout << " { " << (char*)p->range << " }";
#else
        cout << Markup::item();
        cout << p->get_type();
        cout << "\t" << Markup::emphasis(key);

        if ( p->deflt )
            cout << "\t" << (char*)p->deflt;
        else
            cout << "\t";

        cout << "\t" << p->help;

        if ( p->range )
            cout << "\t" << (const char*)p->range;
        else
            cout << "\t";

#endif
        cout << endl;
    }
    key.erase(n);
}

static void dump_table(string& key, const char* pfx, const Parameter* p, bool list)
{
    while ( p->name )
        dump_field(key, pfx, p++, list);
}

//-------------------------------------------------------------------------
// set methods
//-------------------------------------------------------------------------

static const Parameter* get_params(string& sfx, const Parameter* p)
{
    size_t pos = sfx.find_first_of('.');

    if ( pos == string::npos )
        return p;

    sfx.erase(0, pos+1);
    string name = sfx.substr(0, sfx.find_first_of('.'));

    while ( p->name && name != p->name )
        ++p;

    if ( !p->name )
        return nullptr;

    if ( p->type != Parameter::PT_TABLE &&
         p->type != Parameter::PT_LIST )
        return p;

    p = (const Parameter*)p->range;
    return get_params(sfx,  p);
}

// FIXIT vars may have been defined on command line
// that mechanism will be replaced with pulling a Lua
// chunk from the command line and stuffing into L
// before setting configs; that will overwrite
//
// FIXIT should only need one table with
// dynamically typed vars
//
// FIXIT this is a hack to tell vars by naming
// convention; with one table this is obviated
// but if multiple tables are kept might want
// to change these to a module with parameters
static bool set_var(const char* fqn, Value& val)
{
    if ( val.get_type() != Value::VT_STR )
        return false;

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
    if ( !mod->set(fqn, val, s_config) )
    {
        ErrorMessage("ERROR: %s is invalid\n", fqn);
        ++s_errors;
    }

    trace("par", fqn, val);
    return true;
}

static bool set_value(const char* fqn, Value& v)
{
    string mod_name = fqn;
    set_top(mod_name);

    Module* mod = ModuleManager::get_module(mod_name.c_str());

    if ( !mod )
        return set_var(fqn, v);

    // now we must traverse the mod params to get the leaf
    string s = fqn;
    const Parameter* p = get_params(s, mod->get_parameters());
 
    if ( !p )
    {
        FatalError("can't find %s\n", fqn);
        // error messg
        return false;
    }

    if ( p->validate(v) )
    {
        v.set(p);
        set_param(mod, fqn, v);
        return true;
    }

    if ( v.get_type() == Value::VT_STR )
        ErrorMessage("ERROR invalid %s = %s\n", fqn, v.get_string());
    else if ( v.get_real() == v.get_long() )
        ErrorMessage("ERROR invalid %s = %ld\n", fqn, v.get_long());
    else
        ErrorMessage("ERROR invalid %s = %g\n", fqn, v.get_real());

    ++s_errors;
    return false;
}

//-------------------------------------------------------------------------
// ffi methods
//-------------------------------------------------------------------------

extern "C"
{
    bool open_table(const char*, int);
    void close_table(const char*, int);

    bool set_bool(const char* fqn, bool val);
    bool set_number(const char* fqn, double val);
    bool set_string(const char* fqn, const char* val);
}

bool open_table(const char* s, int idx)
{
    string key = s;
    set_top(key);

    // ips option parameters only using in rules which
    // are non-lua; may be possible to allow a subtable
    // for lua config of ips option globals
    ModHook* h = get_hook(key.c_str());

    if ( !h || (h->api && h->api->type == PT_IPS_OPTION) )
        return false;

    Module* m = h->mod;
    static string last;

    if ( last != key )
    {
        if ( !last.size() )
            LogMessage("Configuring modules:\n");
        LogMessage("\t %s\n", key.c_str());
        last = key;
    }

    m->begin(s, idx, s_config);
    return true;
}

void close_table(const char* s, int idx)
{
    string key = s;
    set_top(key);

    if ( ModHook* h = get_hook(key.c_str()) )
    {
        h->mod->end(s, idx, s_config);

        if ( !idx && h->api && (key == s) )
            PluginManager::instantiate(h->api, h->mod, s_config);
    }
}

bool set_bool(const char* fqn, bool b)
{
    Value v(b);
    return set_value(fqn, v);
}

bool set_number(const char* fqn, double d)
{
    Value v(d);
    return set_value(fqn, v);
}

bool set_string(const char* fqn, const char* s)
{
    Value v(s);
    return set_value(fqn, v);
}

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
    for ( auto* p : s_modules )
        delete p;

    s_modules.clear();
}

void ModuleManager::add_module(Module* m, const BaseApi* b)
{
    ModHook* mh = new ModHook(m, b);
    s_modules.push_back(mh);

    if ( mh->reg )
        Shell::install(m->get_name(), mh->reg);

#ifdef PERF_PROFILING
    RegisterProfile(m);
#endif
}

Module* ModuleManager::get_module(const char* s)
{
    for ( auto p : s_modules )
        if ( !strcmp(p->mod->get_name(), s) )
            return p->mod;

    return nullptr;
}

void ModuleManager::set_config(SnortConfig* sc)
{ s_config = sc; }

unsigned ModuleManager::get_errors()
{
    unsigned err = s_errors;
    s_errors = 0;
    return err;
}

void ModuleManager::list_modules()
{
    s_modules.sort(comp_mods);

    for ( auto* p : s_modules )
        LogMessage("%s\n", p->mod->get_name());
}

void ModuleManager::dump_modules()
{
    s_modules.sort(comp_mods);
    Dumper d("Modules");

    for ( auto* p : s_modules )
        if ( !p->api )
            d.dump(p->mod->get_name());
}

static const char* mod_type(const BaseApi* api)
{
    if ( !api )
        return "basic";

    return PluginManager::get_type_name(api->type);
}

void ModuleManager::show_module(const char* name)
{
    if ( !name || !*name )
    {
        cerr << "module name required" << endl;
        return;
    }
    s_modules.sort(comp_gids);

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;
        assert(m);

        if ( strcmp(m->get_name(), name) )
            continue;

        cout << endl << Markup::head() << name << endl << endl;
        cout << "Type: "  << mod_type(p->api) << endl << endl;

        if ( const Parameter* p = m->get_parameters() )
        {
            if ( p->type < Parameter::PT_MAX )
            {
                cout << endl << "Configuration: "  << endl << endl;
                show_configs(name);
            }
        }

        if ( m->get_commands() )
        {
            cout << endl << "Commands: "  << endl << endl;
            show_commands(name);
        }

        if ( m->get_rules() )
        {
            cout << endl << "Rules: "  << endl << endl;
            show_rules(name);
        }

        if ( m->get_pegs() )
        {
            cout << endl << "Peg counts: "  << endl << endl;
            show_pegs(name);
        }
    }
}

void ModuleManager::show_configs(const char* pfx)
{
    s_modules.sort(comp_mods);

    for ( auto p : s_modules )
    {
        Module* m = p->mod;
        string s;

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
        if ( !pfx )
            cout << endl;
    }
}

void ModuleManager::show_commands(const char* pfx)
{
    s_modules.sort(comp_mods);
    unsigned len = pfx ? strlen(pfx) : 0;

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;

        if ( pfx && strncmp(m->get_name(), pfx, len) )
            continue;

        const Command* c = m->get_commands();

        if ( !c )
            continue;
        
        while ( c->name )
        {
            cout << Markup::item();
            cout << Markup::emphasis_on();
            cout << p->mod->get_name();
            cout << "." << c->name;
            cout << Markup::emphasis_off();
            cout << "(): " << c->help;
            cout << endl;
            c++;
        }
    }
}

void ModuleManager::show_gids(const char* pfx)
{
    s_modules.sort(comp_gids);
    unsigned len = pfx ? strlen(pfx) : 0;

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;
        assert(m);

        if ( pfx && strncmp(m->get_name(), pfx, len) )
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
    }    
}

void ModuleManager::show_pegs(const char* pfx)
{
    s_modules.sort(comp_gids);
    unsigned len = pfx ? strlen(pfx) : 0;

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;
        assert(m);

        if ( pfx && strncmp(m->get_name(), pfx, len) )
            continue;

        const char** pegs = m->get_pegs();

        if ( !pegs )
            continue;

        while ( *pegs )
        {
            cout << Markup::item();
            cout << Markup::emphasis_on();
            cout << *pegs;
            cout << Markup::emphasis_off();
            cout << endl;
            ++pegs;
        }
    }    
}

void ModuleManager::show_rules(const char* pfx)
{
    s_modules.sort(comp_gids);
    unsigned len = pfx ? strlen(pfx) : 0;

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;

        if ( pfx && strncmp(m->get_name(), pfx, len) )
            continue;

        const RuleMap* r = m->get_rules();
        unsigned gid = m->get_gid();

        if ( !r )
            continue;

        while ( r->msg )
        {
            cout << Markup::item();
            cout << Markup::emphasis_on();
            cout << gid << ":" << r->sid;
            cout << Markup::emphasis_off();
            cout << " " << r->msg;
            cout << endl;
            r++;
        }
    }    
}

void ModuleManager::load_rules(SnortConfig* sc)
{
    // FIXIT callers of ParseConfigString() should not have to push parse loc
    push_parse_location("builtin");

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;
        const RuleMap* r = m->get_rules();
        unsigned gid = m->get_gid();

        if ( !r )
            continue;

        stringstream ss;

        while ( r->msg )
        {
            ss.str("");
            // FIXIT move builtin generation to a better home
            // FIXIT builtins should allow configurable nets and ports
            // FIXIT builtins should have accurate proto
            //       (but ip winds up in all others)
            // FIXIT if msg has C escaped embedded quotes, we break
            ss << "alert tcp any any -> any any ( ";
            ss << "gid:" << gid << "; ";
            ss << "sid:" << r->sid << "; ";
            ss << "msg:\"" << r->msg << "\"; )";
            ss << endl;

            // note:  you can NOT do ss.str().c_str() here
            const string& rule = ss.str();
            ParseConfigString(sc, rule.c_str());

            r++;
        }
    }    
    pop_parse_location();
}

void ModuleManager::dump_stats (SnortConfig*)
{
    for ( auto p : s_modules )
        p->mod->show_stats();
}

void ModuleManager::accumulate (SnortConfig*)
{
    static mutex stats_mutex;
    stats_mutex.lock();

    for ( auto p : s_modules )
        p->mod->sum_stats();

    pc_sum();
    stats_mutex.unlock();
}

void ModuleManager::reset_stats (SnortConfig*)
{
    for ( auto p : s_modules )
        p->mod->reset_stats();
}

