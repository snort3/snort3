//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// mpse.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpse.h"

#include <cassert>

#include "profiler/profiler_defs.h"
#include "search_engines/pat_stats.h"
#include "managers/mpse_manager.h"
#include "managers/module_manager.h"
#include "main/snort_config.h"
#include "detection/fp_config.h"

#include "mpse_batch.h"

using namespace std;

namespace snort
{

//-------------------------------------------------------------------------
// base stuff
//-------------------------------------------------------------------------

Mpse::Mpse(const char* m)
{
    method = m;
    verbose = 0;
    api = nullptr;
}

int Mpse::search(
    const unsigned char* T, int n, MpseMatch match,
    void* context, int* current_state)
{
    pmqs.matched_bytes += n;
    return _search(T, n, match, context, current_state);
}

int Mpse::search_all(
    const unsigned char* T, int n, MpseMatch match,
    void* context, int* current_state)
{
    pmqs.matched_bytes += n;
    return _search(T, n, match, context, current_state);
}

void Mpse::search(MpseBatch& batch, MpseType mpse_type)
{
    _search(batch, mpse_type);
}

void Mpse::_search(MpseBatch& batch, MpseType mpse_type)
{
    int start_state;

    for ( auto& item : batch.items )
    {
        if (item.second.done)
            continue;

        item.second.error = false;
        item.second.matches = 0;

        for ( auto& so : item.second.so )
        {
            start_state = 0;

            Mpse* mpse = (mpse_type == MPSE_TYPE_OFFLOAD) ?
                so->get_offload_mpse() : so->get_normal_mpse();

            item.second.matches += mpse->search(
                item.first.buf, item.first.len, batch.mf, batch.context, &start_state);
        }
        item.second.done = true;
    }
}

Mpse::MpseRespType Mpse::poll_responses(MpseBatch*& batch, MpseType mpse_type)
{
    // FIXIT-L validate for reload during offload
    FastPatternConfig* fp = SnortConfig::get_conf()->fast_pattern_config;
    assert(fp);

    const MpseApi* search_api = nullptr;

    switch (mpse_type)
    {
    case MPSE_TYPE_NORMAL:
        search_api = fp->get_search_api();
        break;

    case MPSE_TYPE_OFFLOAD:
        search_api = fp->get_offload_search_api();

        if (!search_api)
            search_api = fp->get_search_api();
        break;
    }

    if (search_api)
    {
        assert(search_api->poll);
        return search_api->poll(batch, mpse_type);
    }

    return MPSE_RESP_NOT_COMPLETE;
}

}

