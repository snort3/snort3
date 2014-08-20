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
// ips_manager.cc author Russ Combs <rucombs@cisco.com>

#include "ips_manager.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <list>
#include <fstream>
using namespace std;

#include "snort_types.h"
#include "plugin_manager.h"
#include "framework/ips_option.h"
#include "framework/so_rule.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "managers/module_manager.h"
#include "ips_options/ips_options.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"
#include "parser/parser.h"
#include "log/messages.h"

struct Option
{
    const IpsApi* api;
    bool init;

    Option(const IpsApi* p)
    { api = p; init = false; };
};

typedef list<Option*> OptionList;
static OptionList s_options;

static const char* current_keyword = nullptr;
static Module* current_module = nullptr;
static const Parameter* current_params = nullptr;

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

void IpsManager::add_plugin(const IpsApi* api)
{
    s_options.push_back(new Option(api));
}

void IpsManager::release_plugins()
{
    for ( auto* p : s_options )
        delete p;

    s_options.clear();
}

void IpsManager::dump_plugins()
{
    Dumper d("IPS Options");

    for ( auto* p : s_options )
        d.dump(p->api->base.name, p->api->base.version);
}

//-------------------------------------------------------------------------
// ips options
//-------------------------------------------------------------------------

void IpsManager::delete_option(IpsOption* ips)
{
    const IpsApi* api = (const IpsApi*)
        PluginManager::get_api(PT_IPS_OPTION, ips->get_name());

    if ( api )
        api->dtor(ips);
}

    
//-------------------------------------------------------------------------

static bool is_positional(const Parameter* p)
{
    return ( p->name && *p->name == '~' );
}

static const Parameter* find_arg(const Parameter* p, const char* s)
{
    while ( p->name )
    {
        if ( !strcmp(p->name, s) || !strcmp(p->name, "*") )
            return p;
        ++p;
    }
    return nullptr;
}

static bool set_arg(
    Module* m, const Parameter* p, 
    const char* opt, const char* val, SnortConfig* sc)
{
    if ( !is_positional(p) )
        p = find_arg(p, opt);

    if ( !p )
        return false;

    Value v(opt);
    bool ok = true;

    if ( p->type == Parameter::PT_IMPLIED )
        v.set(true);

    else if ( p->type == Parameter::PT_INT )
    {
        char* end = nullptr;
        long n = strtol(val, &end, 0);

        if ( !*end )
            v.set(n);
        else
            ok = false;
    }
    else
        v.set(val);

    if ( ok && p->validate(v) )
    {
        v.set(p);

        if ( m->set(p->name, v, sc) )
            return true;
    }

    return false;
}

//-------------------------------------------------------------------------

static Option* get_opt(const char *keyword)
{
    for ( auto* p : s_options )
        if ( !strcasecmp(p->api->base.name, keyword) )
            return p;

    return nullptr;
}

const char* IpsManager::get_option_keyword()
{
    return current_keyword;
}

bool IpsManager::option_begin(
    SnortConfig* sc, const char* key)
{
    Option* opt = get_opt(key);

    if ( !opt )
        return false;

    if ( !opt->init )
    {
        if ( opt->api->pinit )
            opt->api->pinit(sc);
        opt->init = true;
    }
    // FIXIT verify api->protos and api->max_per_rule
    // before calling ctor
    current_module = ModuleManager::get_module(key);

    if ( current_module && !current_module->begin(key, 0, sc) )
    {
        ParseError("can't initialize %s", key);
        return false;
    }
    current_keyword = key;
    current_params = current_module ? current_module->get_parameters() : nullptr;
    return true;
}

bool IpsManager::option_set(
    SnortConfig* sc, const char* key, const char* opt, const char* val)
{
    if ( !current_module || !current_keyword )
        return false;

    assert(!strcmp(current_keyword, key));

    if ( !*val && is_positional(current_params) )
    {
        val = opt;  // eg: gid:116; key="gid" and opt="116"
        opt = "";
    }

    if ( !set_arg(current_module, current_params, opt, val, sc) )
        ParseError("invalid argument %s:%s = %s\n", key, opt, val);

    if ( is_positional(current_params) )
        ++current_params;

    return true;
}

bool IpsManager::option_end(
    SnortConfig* sc, OptTreeNode* otn, int proto,
    const char* key, RuleOptType& type)
{
    if ( !current_keyword )
        return false;

    assert(!strcmp(current_keyword, key));

#ifdef NDEBUG
    UNUSED(proto);
#else
    assert(proto == otn->proto);
#endif

    Module* mod = current_module;
    current_module = nullptr;
    current_params = nullptr;

    if ( mod && !mod->end(key, 0, sc) )
    {
        ParseError("can't finalize %s\n", key);
        current_keyword = nullptr;
        return false;
    }
    
    Option* opt = get_opt(key);
    assert(opt);

    IpsOption* ips = opt->api->ctor(mod, otn);
    type = opt->api->type;
    current_keyword = nullptr;

    if ( !ips )
        return ( type == OPT_TYPE_META );

    void* dup;

    if ( !add_detection_option(
        sc, ips->get_type(), ips, &dup) )
    {
        delete ips;
        ips = (IpsOption*)dup;
    }

    OptFpList* fpl = AddOptFuncToList(IpsOption::eval, otn);
    fpl->context = ips;
    fpl->type = ips->get_type();

    if ( ips->is_relative() )
        fpl->isRelative = 1;

    otn_set_plugin(otn, ips->get_type());
    return true;
}

//-------------------------------------------------------------------------

void IpsManager::global_init(SnortConfig*)
{
}

void IpsManager::global_term(SnortConfig* sc)
{
    for ( auto* p : s_options )
        if ( p->init && p->api->pterm )
        {
            p->api->pterm(sc);
            p->init = false;
        }
}

void IpsManager::setup_options()
{
    for ( auto* p : s_options )
        if ( p->init && p->api->tinit )
            p->api->tinit(snort_conf);
}

void IpsManager::clear_options()
{
    for ( auto* p : s_options )
        if ( p->init && p->api->tterm )
            p->api->tterm(snort_conf);
}

bool IpsManager::verify(SnortConfig* sc)
{
    for ( auto* p : s_options )
        if ( p->init && p->api->verify )
            p->api->verify(sc);

    return true;
}

