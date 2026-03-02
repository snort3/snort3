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
// mpse_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpse_manager.h"

#include <cassert>
#include <list>

#include "detection/fp_config.h"
#include "framework/mpse.h"
#include "main/snort_config.h"

#include "plugin_manager.h"
#include "plug_interface.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// engine plugins
//-------------------------------------------------------------------------

PlugInterface* MpseManager::get_interface(const MpseApi*)
{ return new PlugInterface; }

const MpseApi* MpseManager::get_search_api(const char* name)
{
    const MpseApi* api = (const MpseApi*)PluginManager::get_api(name);

    if ( api and api->init )
        api->init();

    return api;
}

Mpse* MpseManager::get_search_engine(
    const SnortConfig* sc, const MpseApi* api, const MpseAgent* agent)
{
    Module* mod = PluginManager::get_module(api->base.name);
    Mpse* eng = api->ctor(sc, mod, agent);
    eng->set_api(api);
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
    if ( api->print )
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

bool MpseManager::is_async_capable(const MpseApi* api)
{
    assert(api);
    return (api->flags & MPSE_ASYNC) != 0;
}

bool MpseManager::is_regex_capable(const MpseApi* api)
{
    assert(api);
    return (api->flags & MPSE_REGEX) != 0;
}

bool MpseManager::is_poll_capable(const MpseApi* api)
{
    assert(api);
    return (api->poll);
}

bool MpseManager::parallel_compiles(const MpseApi* api)
{
    assert(api);
    return (api->flags & MPSE_MTBLD) != 0;
}

