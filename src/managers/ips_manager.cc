//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_manager.h"

#include <cassert>
#include <map>

#include "detection/fp_detect.h"
#include "detection/treenodes.h"
#include "framework/ips_info.h"
#include "log/messages.h"
#include "main/snort_config.h"

#include "module_manager.h"
#include "plugin_manager.h"

using namespace snort;
using namespace std;

struct Option
{
    const IpsApi* api;
    bool init;
    unsigned count;

    Option(const IpsApi* p)
    { api = p; init = false; count = 0; }
};

typedef map<std::string, Option*> OptionMap;
static OptionMap s_options;

static std::string current_keyword = std::string();
static Module* current_module = nullptr;
static const Parameter* current_params = nullptr;

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

void IpsManager::add_plugin(const IpsApi* api)
{
    assert(s_options.find(api->base.name) == s_options.end());
    s_options[api->base.name] = new Option(api);
}

void IpsManager::release_plugins()
{
    for ( const auto& p : s_options )
        delete p.second;

    s_options.clear();
}

void IpsManager::dump_plugins()
{
    Dumper d("IPS Options");

    for ( auto& p : s_options )
        d.dump(p.second->api->base.name, p.second->api->base.version);
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

static bool set_arg(
    Module* m, const Parameter* p,
    const char* opt, const char* val, SnortConfig* sc)
{
    if ( !p->is_positional() )
    {
        const Parameter* q = ModuleManager::get_parameter(m->get_name(), opt);
        p = q ? q : Parameter::find(p, opt);
    }
    else if ( *opt )  // must contain spaces like ip_proto:! 6;
        return false;

    if ( !p )
        return false;

    Value v(opt);
    bool ok = true;

    if ( p->type == Parameter::PT_IMPLIED )
        v.set(true);

    else if ( p->type == Parameter::PT_BOOL )
    {
        if ( !val or !strcmp(val, "true") )
            v.set(true);
        else
            v.set(false);
    }
    else if ( p->type == Parameter::PT_INT )
    {
        char* end = nullptr;

        if ( p->is_wild_card() )
            val = opt;

        int64_t n = strtoll(val, &end, 0);

        if ( !*end )
            v.set((double)n);
        else
            ok = false;
    }
    else if ( p->is_wild_card() )
    {
        string s = opt;
        if ( val and *val )
        {
            s += " ";
            s += val;
        }
        v.set(s.c_str());
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

static Option* get_opt(const char* keyword)
{
    auto opt = s_options.find(keyword);
    if ( opt != s_options.end() )
        return opt->second;

    return nullptr;
}

const char* IpsManager::get_option_keyword()
{
    return current_keyword.c_str();
}

const IpsApi* IpsManager::get_option_api(const char* keyword)
{
    Option* opt = get_opt(keyword);
    if ( opt )
        return opt->api;
    else
        return nullptr;
}

bool IpsManager::option_begin(
    SnortConfig* sc, const char* key, SnortProtocolId)
{
    Option* opt = get_opt(key);

    if ( !opt )
    {
        ParseError("unknown rule keyword: %s.", key);
        return false;
    }

    if ( !opt->init )
    {
        if ( opt->api->pinit )
            opt->api->pinit(sc);
        opt->init = true;
    }

    if ( opt->api->max_per_rule && (++opt->count > opt->api->max_per_rule) )
    {
        ParseError("%s allowed only %u time(s) per rule",
            opt->api->base.name, opt->api->max_per_rule);
        return false;
    }

    // FIXIT-M allow service too
    //if ( opt->api->protos && !(proto & opt->api->protos) )
    //{
    //    ParseError("%s not allowed with given rule protocol", opt->api->base.name);
    //    return false;
    //}

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
    if ( !current_module || current_keyword.empty() )
        return false;

    assert(!strcmp(current_keyword.c_str(), key));
    std::string munge;

    if ( current_params->is_positional() )
    {
        if ( !*val )  // eg: gid:116; opt="116", val="" -> opt="", val="116"
        {
            val = opt;
            opt = "";
        }
        else       // eg: dsize:> 80; opt=">", val="80" -> opt="", val="> 80"
        {
            munge = opt;
            munge += " ";
            munge += val;
            val = munge.c_str();
            opt = "";
        }
    }

    if ( !set_arg(current_module, current_params, opt, val, sc) )
        ParseError("invalid argument %s:%s = %s", key, opt, val);

    if ( current_params->is_positional() )
        ++current_params;

    return true;
}

IpsOption* IpsManager::option_end(
    SnortConfig* sc, OptTreeNode* otn, SnortProtocolId snort_protocol_id,
    const char* key, RuleOptType& type)
{
    if ( current_keyword.empty() )
        return nullptr;

    assert(!strcmp(current_keyword.c_str(), key));

#ifdef NDEBUG
    UNUSED(snort_protocol_id);
#else
    assert(snort_protocol_id == otn->snort_protocol_id);
#endif

    Module* mod = current_module;
    current_module = nullptr;
    current_params = nullptr;

    Option* opt = get_opt(key);
    assert(opt);

    if ( !mod and opt->api->base.mod_ctor )
    {
        ParseError("unknown option %s", key);
        current_keyword.clear();
        return nullptr;
    }

    if ( mod and !mod->end(key, 0, sc) )
    {
        ParseError("can't finalize %s", key);
        current_keyword.clear();
        return nullptr;
    }

    IpsInfo info(otn, sc);
    IpsOption* ips = opt->api->ctor(mod, info);
    type = opt->api->type;
    current_keyword.clear();

    if ( !ips )
        return nullptr;

    if ( void* prev = add_detection_option(sc, ips->get_type(), ips) )
    {
        delete ips;
        ips = (IpsOption*)prev;
    }

    OptFpList* fpl = AddOptFuncToList(fp_eval_option, otn);
    fpl->ips_opt = ips;
    fpl->type = ips->get_type();

    if ( ips->is_relative() )
        fpl->isRelative = 1;

    if ( ips->is_agent() and !otn_set_agent(otn, ips) )
    {
        // FIXIT-L support multiple actions (eg replaces) per rule
        ParseWarning(WARN_RULES,
            "at most one action per rule is allowed; other actions disabled");
    }
    return ips;
}

//-------------------------------------------------------------------------

void IpsManager::global_init(const SnortConfig*)
{
}

void IpsManager::global_term(const SnortConfig* sc)
{
    for ( const auto& p : s_options )
        if ( p.second->init && p.second->api->pterm )
        {
            p.second->api->pterm(sc);
            p.second->init = false;
        }
}

void IpsManager::reset_options()
{
    for ( const auto& p : s_options )
        p.second->count = 0;
}

void IpsManager::setup_options(const SnortConfig* sc)
{
    for ( const auto& p : s_options )
        if ( p.second->init && p.second->api->tinit )
            p.second->api->tinit(sc);
}

void IpsManager::clear_options(const SnortConfig* sc)
{
    for ( const auto& p : s_options )
        if ( p.second->init && p.second->api->tterm )
            p.second->api->tterm(sc);
}

bool IpsManager::verify(SnortConfig* sc)
{
    for ( const auto& p : s_options )
        if ( p.second->init && p.second->api->verify )
            p.second->api->verify(sc);

    return true;
}

