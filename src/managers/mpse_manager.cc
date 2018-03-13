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
// mpse_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpse_manager.h"

#include <cassert>
#include <list>

#include "detection/fp_config.h"
#include "framework/mpse.h"
#include "log/messages.h"
#include "main/snort_config.h"

#include "module_manager.h"

using namespace snort;
using namespace std;

typedef list<const MpseApi*> EngineList;
static EngineList s_engines;

//-------------------------------------------------------------------------
// engine plugins
//-------------------------------------------------------------------------

void MpseManager::add_plugin(const MpseApi* api)
{
    s_engines.push_back(api);
}

void MpseManager::release_plugins()
{
    s_engines.clear();
}

void MpseManager::dump_plugins()
{
    Dumper d("Search Engines");

    for ( auto* p : s_engines )
        d.dump(p->base.name, p->base.version);
}

//-------------------------------------------------------------------------

void MpseManager::instantiate(const MpseApi*, Module*, SnortConfig*)
{
    // nothing to do here
    // see
}

static const MpseApi* get_api(const char* keyword)
{
    for ( auto* p : s_engines )
        if ( !strcasecmp(p->base.name, keyword) )
            return p;

    return nullptr;
}

const MpseApi* MpseManager::get_search_api(const char* name)
{
    const MpseApi* api = ::get_api(name);

    if ( api )
        api->init();

    return api;
}

Mpse* MpseManager::get_search_engine(
    SnortConfig* sc, const MpseApi* api, const MpseAgent* agent)
{
    Module* mod = ModuleManager::get_module(api->base.name);
    Mpse* eng = api->ctor(sc, mod, agent);
    eng->set_api(api);
    return eng;
}

Mpse* MpseManager::get_search_engine(const char* type)
{
    if ( !type and SnortConfig::get_conf()->fast_pattern_config )
        type = SnortConfig::get_conf()->fast_pattern_config->get_search_method();

    if ( !type )
        type = "ac_bnfa";

    const MpseApi* api = get_search_api(type);

    if ( !api )
        return nullptr;

    Module* mod = ModuleManager::get_module(api->base.name);
    Mpse* eng = api->ctor(nullptr, mod, nullptr);
    eng->set_api(api);

    if ( SnortConfig::get_conf()->fast_pattern_config and SnortConfig::get_conf()->fast_pattern_config->get_search_opt() )
        eng->set_opt(1);

    return eng;
}

void MpseManager::delete_search_engine(Mpse* eng)
{
    const MpseApi* api = eng->get_api();
    api->dtor(eng);
}

//-------------------------------------------------------------------------

// the summary info is totaled by type for all instances
void MpseManager::print_mpse_summary(const MpseApi* api)
{
    assert(api);
    api->print();
}

void MpseManager::activate_search_engine(const MpseApi* api, SnortConfig* sc)
{
    assert(api);
    if ( api->activate )
        api->activate(sc);
}

void MpseManager::setup_search_engine(const MpseApi* api, SnortConfig* sc)
{
    assert(api);
    if ( api->setup )
        api->setup(sc);
}

void MpseManager::start_search_engine(const MpseApi* api)
{
    assert(api);
    if ( api->start )
        api->start();
}

void MpseManager::stop_search_engine(const MpseApi* api)
{
    assert(api);
    if ( api->stop )
        api->stop();
}

bool MpseManager::search_engine_trim(const MpseApi* api)
{
    assert(api);
    return (api->flags & MPSE_TRIM) != 0;
}

bool MpseManager::is_regex_capable(const MpseApi* api)
{
    assert(api);
    return (api->flags & MPSE_REGEX) != 0;
}

// was called during drop stats but actually commented out
// FIXIT-M this one has to accumulate across threads
#if 0
void MpseManager::print_qinfo()
{
    sfksearch_print_qinfo();
    acsmx2_print_qinfo();
}

// this is commented out of snort.cc
// combine with above?
void MpseManager::print_search_engine_stats()
{
    IntelPmPrintBufferStats();
}

#endif

#ifdef PIGLET

MpseWrapper* MpseManager::instantiate(const char* name, Module* m, SnortConfig* sc)
{
    auto api = ::get_api(name);

    if ( !api || !api->ctor )
        return nullptr;

    auto p = api->ctor(sc, m, nullptr);

    if ( !p )
        return nullptr;

    return new MpseWrapper(api, p);
}

#endif

