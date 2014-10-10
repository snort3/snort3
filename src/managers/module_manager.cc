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

#include "framework/base_api.h"
#include "framework/module.h"
#include "managers/plugin_manager.h"
#include "main/snort_config.h"
#include "main/modules.h"
#include "main/shell.h"
#include "main/snort_types.h"
#include "parser/parser.h"
#include "parser/parse_conf.h"
#include "parser/vars.h"
#include "time/profiler.h"
#include "helpers/markup.h"
#include "utils/stats.h"

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

typedef list<ModHook*> ModuleList;
static ModuleList s_modules;
static unsigned s_errors = 0;
static string s_current;
static string s_name;
static string s_type;

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

enum DumpFormat { DF_STD, DF_TAB, DF_LUA };
static DumpFormat dump_fmt = DF_STD;

static void dump_field_std(const string& key, const Parameter* p)
{
    cout << Markup::item();
    cout << Markup::sanitize(p->get_type());
    cout << " " << Markup::emphasis(Markup::sanitize(key));

    if ( p->deflt )
        cout << " = " << Markup::sanitize((char*)p->deflt);

    cout << ": " << p->help;

    if ( p->range )
        cout << " { " << Markup::sanitize((char*)p->range) << " }";

    cout << endl;
}

static void dump_field_tab(const string& key, const Parameter* p)
{
    cout << Markup::item();
    cout << p->get_type();
    cout << "\t" << Markup::emphasis(Markup::sanitize(key));

    if ( p->deflt )
        cout << "\t" << Markup::sanitize((char*)p->deflt);
    else
        cout << "\t";

    cout << "\t" << p->help;

    if ( p->range )
        cout << "\t" << Markup::sanitize((char*)p->range);
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
        dump_table(key, pfx, (Parameter*)p->range);

    else if ( p->type == Parameter::PT_LIST )
        dump_table(key, pfx, (Parameter*)p->range, true);

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
    while ( p->name )
        dump_field(key, pfx, p++, list);
}

//-------------------------------------------------------------------------
// set methods
//-------------------------------------------------------------------------

static const Parameter* get_params(const string& sfx, const Parameter* p)
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
    while ( p->name && name != p->name )
        ++p;

    if ( !p->name )
        return nullptr;

    if ( p->type != Parameter::PT_TABLE &&
         p->type != Parameter::PT_LIST )
        return p;

    if (new_fqn.find_first_of('.') == std::string::npos)
    {
        if (p->type == Parameter::PT_LIST)
        {
            const Parameter* tmp_p =
                reinterpret_cast<const Parameter*>(p->range);

            // FIXIT -- this will fail if we are opening a
            // a list with only one Parameter
            if ( tmp_p[0].name && !tmp_p[1].name )
                return tmp_p;
        }
        return p;
    }

    p = (const Parameter*)p->range;
    return get_params(new_fqn, p);
}

// FIXIT-M vars may have been defined on command line
// that mechanism will be replaced with pulling a Lua
// chunk from the command line and stuffing into L
// before setting configs; that will overwrite
//
// FIXIT-M should only need one table with
// dynamically typed vars
//
// FIXIT-M this is a hack to tell vars by naming
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
        ParseError("%s is invalid", fqn);
        ++s_errors;
    }

    trace("par", fqn, val);
    return true;
}

static bool ignored(const char* fqn)
{
    static const char* ignore = nullptr;

    if ( !(snort_conf->logging_flags & LOGGING_FLAG__WARN_UNKNOWN) )
        return true;

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
            ParseWarning("uknown symbol %s", fqn);
        return found;
    }

    // now we must traverse the mod params to get the leaf
    string s = fqn;
    const Parameter* p = get_params(s, mod->get_parameters());
 
    if ( !p )
    {
        // FIXIT-L handle things like x = { 1 }
        // where x is a table not a list and 1 should be 
        // considered a key not a value; ideally say
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
    else if ( v.get_real() == v.get_long() )
        ParseError("invalid %s = %ld", fqn, v.get_long());
    else
        ParseError("invalid %s = %g", fqn, v.get_real());

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
    bool set_alias(const char* from, const char* to);
}

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

    // ips option parameters only using in rules which
    // are non-lua; may be possible to allow a subtable
    // for lua config of ips option globals
    ModHook* h = get_hook(key.c_str());

    if ( !h || (h->api && h->api->type == PT_IPS_OPTION) )
        return false;

    //printf("open %s %d\n", s, idx);
    Module* m = h->mod;

    if (strcmp(m->get_name(), s))
    {
        std::string fqn = s;
        const Parameter* const p = get_params(fqn, m->get_parameters());

        if ( !p )
        {
            ParseError("can't find %s", s);
            return false;
        }
        else if ((idx > 0) && (p->type == Parameter::PT_TABLE))
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

    if ( !m->begin(s, idx, s_config) )
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

    //printf("close %s %d\n", s, idx);

    if ( ModHook* h = get_hook(key.c_str()) )
    {
        if ( !h->mod->end(s, idx, s_config) )
            ParseError("can't close %s", h->mod->get_name());

        else if ( !s_name.empty() )
            PluginManager::instantiate(h->api, h->mod, s_config, s_name.c_str());

        else if ( !idx && h->api && (key == s) )
            PluginManager::instantiate(h->api, h->mod, s_config);
    }
    s_name.clear();
    s_type.clear();
}

SO_PUBLIC bool set_bool(const char* fqn, bool b)
{
    //printf("bool %s %d\n", fqn, b);
    Value v(b);
    return set_value(fqn, v);
}

SO_PUBLIC bool set_number(const char* fqn, double d)
{
    //printf("real %s %f\n", fqn, d);
    Value v(d);
    return set_value(fqn, v);
}

SO_PUBLIC bool set_string(const char* fqn, const char* s)
{
    //printf("string %s %s\n", fqn, s);
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

const char* ModuleManager::get_current_module()
{ return s_current.c_str(); }

void ModuleManager::set_config(SnortConfig* sc)
{ s_config = sc; }

void ModuleManager::reset_errors()
{ s_errors = 0; }

unsigned ModuleManager::get_errors()
{ return s_errors; }

void ModuleManager::list_modules()
{
    s_modules.sort(comp_mods);

    for ( auto* p : s_modules )
        LogMessage("%s\n", p->mod->get_name());
}

void ModuleManager::show_modules()
{
    s_modules.sort(comp_mods);

    for ( auto* p : s_modules )
        LogMessage("%s: %s\n", p->mod->get_name(), p->mod->get_help());
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
    unsigned c = 0;

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;
        assert(m);

        if ( strcmp(m->get_name(), name) )
            continue;

        cout << endl << Markup::head() << Markup::sanitize(name) << endl << endl;

        if ( const char* h = m->get_help() )
            cout << endl << "What: " << Markup::sanitize(h) << endl;

        cout << endl << "Type: "  << mod_type(p->api) << endl;

        if ( const Parameter* p = m->get_parameters() )
        {
            if ( p->type < Parameter::PT_MAX )
            {
                cout << endl << "Configuration: " << endl << endl;
                show_configs(name, true);
            }
        }

        if ( m->get_commands() )
        {
            cout << endl << "Commands: " << endl << endl;
            show_commands(name);
        }

        if ( m->get_rules() )
        {
            cout << endl << "Rules: " << endl << endl;
            show_rules(name);
        }

        if ( m->get_pegs() )
        {
            cout << endl << "Peg counts: " << endl << endl;
            show_pegs(name);
        }
        c++;
    }
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::show_configs(const char* pfx, bool exact)
{
    s_modules.sort(comp_mods);
    unsigned c = 0;

    for ( auto p : s_modules )
    {
        Module* m = p->mod;
        string s;

        if ( pfx )
        {
            if ( exact && strcmp(m->get_name(), pfx) )
                continue;
            else if ( !exact && strncmp(m->get_name(), pfx, strlen(pfx)) )
                continue;
        }

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

void ModuleManager::show_commands(const char* pfx)
{
    s_modules.sort(comp_mods);
    unsigned len = pfx ? strlen(pfx) : 0;
    unsigned n = 0;

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
            cout << Markup::sanitize(p->mod->get_name());
            cout << "." << Markup::sanitize(c->name);
            cout << Markup::emphasis_off();
            cout << "(): " << Markup::sanitize(c->help);
            cout << endl;
            c++;
        }
        n++;
    }
    if ( !n )
        cout << "no match" << endl;
}

void ModuleManager::show_gids(const char* pfx)
{
    s_modules.sort(comp_gids);
    unsigned len = pfx ? strlen(pfx) : 0;
    unsigned c = 0;

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
            cout << ": " << Markup::sanitize(m->get_name());
            cout << endl;
        }
        c++;
    }    
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::show_pegs(const char* pfx)
{
    s_modules.sort(comp_gids);
    unsigned len = pfx ? strlen(pfx) : 0;
    unsigned c = 0;

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
            cout << Markup::sanitize(*pegs);
            cout << Markup::emphasis_off();
            cout << endl;
            ++pegs;
        }
        c++;
    }    
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::show_rules(const char* pfx)
{
    s_modules.sort(comp_gids);
    unsigned len = pfx ? strlen(pfx) : 0;
    unsigned c = 0;

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
            cout << " (" << m->get_name() << ")";
            cout << " " << Markup::sanitize(r->msg);
            cout << endl;
            r++;
        }
        c++;
    }    
    if ( !c )
        cout << "no match" << endl;
}

void ModuleManager::load_commands(SnortConfig* sc)
{
    // FIXIT-L ideally only install commands from configured modules
    // FIXIT-L install commands into working shell
    Shell* sh = sc->policy_map->get_shell();

    for ( auto p : s_modules )
    {
        if ( p->reg )
            sh->install(p->mod->get_name(), p->reg);
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
    os << "msg:\"" << "(" << m->get_name() << ") ";
    os << r->msg << "\"; )";
    os << endl;
}

// FIXIT-L currently no way to know whether a module was activated or not
// so modules with common rules will cause duplicate sid warnings
// eg http_inspect and nhttp_inspect both have 119:1-34
// only way to avoid that now is to not load plugins with common rules
// (we don't want to suppress it because it could mean something is broken)
void ModuleManager::load_rules(SnortConfig* sc)
{
    s_modules.sort(comp_gids);
    push_parse_location("builtin");

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;
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
            ParseConfigString(sc, rule.c_str());

            r++;
        }
    }    
    pop_parse_location();
}

void ModuleManager::dump_rules(const char* pfx)
{
    s_modules.sort(comp_gids);
    unsigned len = pfx ? strlen(pfx) : 0;
    unsigned c = 0;

    for ( auto p : s_modules )
    {
        const Module* m = p->mod;

        if ( pfx && strncmp(m->get_name(), pfx, len) )
            continue;

        const RuleMap* r = m->get_rules();

        if ( !r )
            continue;

        ostream& ss = cout;

        while ( r->msg )
        {
            make_rule(ss, m, r);
            r++;
        }
        c++;
    }    
    if ( !c )
        cout << "no match" << endl;
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

