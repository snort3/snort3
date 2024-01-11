//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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
// mpse_batch.cc author Titan IC Systems <support@titan-ic.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpse_batch.h"

#include "profiler/profiler_defs.h"
#include "search_engines/pat_stats.h"
#include "managers/mpse_manager.h"
#include "managers/module_manager.h"
#include "main/snort_config.h"
#include "detection/fp_config.h"

#include <cassert>

using namespace std;

namespace snort
{

//-------------------------------------------------------------------------
// batch stuff
//-------------------------------------------------------------------------

bool MpseBatch::search_sync()
{
    bool searches = false;

    if (items.size() > 0)
    {
        Mpse::MpseRespType resp_ret;
        searches = true;

        search();
        do
        {
            resp_ret = receive_responses();
        }
        while (resp_ret == Mpse::MPSE_RESP_NOT_COMPLETE);

        // Assumption here is that a normal search engine will never fail
    }
    items.clear();

    return searches;
}

//-------------------------------------------------------------------------
// group stuff
//-------------------------------------------------------------------------

MpseGroup::~MpseGroup()
{
    if (normal_mpse)
    {
        if (!normal_is_dup)
            MpseManager::delete_search_engine(normal_mpse);
        normal_mpse = nullptr;
    }
    if (offload_mpse)
    {
        if (!offload_is_dup)
            MpseManager::delete_search_engine(offload_mpse);
        offload_mpse = nullptr;
    }
}

bool MpseGroup::create_normal_mpse(const SnortConfig* sc, const MpseAgent* agent)
{
    const FastPatternConfig* fp = sc->fast_pattern_config;
    const MpseApi* search_api = nullptr;

    if (fp)
        search_api = fp->get_search_api();

    if (search_api != nullptr)
    {
        normal_mpse = MpseManager::get_search_engine(sc, search_api, agent);
        return true;
    }
    else
    {
        normal_mpse = nullptr;
        return false;
    }
}

bool MpseGroup::create_normal_mpse(const SnortConfig* sc, const char* type)
{
    if ( !type and sc->fast_pattern_config )
        type = sc->fast_pattern_config->get_search_method();

    if ( !type )
        type = "ac_bnfa";

    const MpseApi* search_api = MpseManager::get_search_api(type);

    if (search_api)
    {
        Module* mod = ModuleManager::get_module(search_api->base.name);
        normal_mpse = search_api->ctor(sc, mod, nullptr);
        normal_mpse->set_api(search_api);
        return true;
    }
    else
    {
        normal_mpse = nullptr;
        return false;
    }
}

bool MpseGroup::create_offload_mpse(const SnortConfig* sc, const MpseAgent* agent)
{
    const FastPatternConfig* fp = sc->fast_pattern_config;
    const MpseApi* search_api = nullptr;
    const MpseApi* offload_search_api = nullptr;

    if (fp)
    {
        search_api = fp->get_search_api();
        offload_search_api = fp->get_offload_search_api();
    }

    if (offload_search_api and (offload_search_api != search_api))
    {
        offload_mpse = MpseManager::get_search_engine(sc, offload_search_api, agent);
        return true;
    }
    else
    {
        offload_mpse = nullptr;
        return false;
    }
}

bool MpseGroup::create_offload_mpse(const SnortConfig* sc)
{
    const MpseApi* search_api = nullptr;
    const MpseApi* offload_search_api = nullptr;

    if (sc->fast_pattern_config )
    {
        search_api = sc->fast_pattern_config->get_search_api();
        offload_search_api = sc->fast_pattern_config->get_offload_search_api();
    }

    if (offload_search_api and (offload_search_api != search_api))
    {
        Module* mod = ModuleManager::get_module(offload_search_api->base.name);
        offload_mpse = offload_search_api->ctor(sc, mod, nullptr);
        offload_mpse->set_api(offload_search_api);
        return true;
    }
    else
    {
        offload_mpse = nullptr;
        return false;
    }
}

}

