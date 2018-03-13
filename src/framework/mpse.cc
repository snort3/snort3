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
// mpse.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mpse.h"

#include "profiler/profiler_defs.h"
#include "search_engines/pat_stats.h"


using namespace std;

namespace snort
{
THREAD_LOCAL ProfileStats mpsePerfStats;

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
    Profile profile(mpsePerfStats);

    int ret = _search(T, n, match, context, current_state);

    pmqs.matched_bytes += n;

    return ret;
}

int Mpse::search_all(
    const unsigned char* T, int n, MpseMatch match,
    void* context, int* current_state)
{
    return _search(T, n, match, context, current_state);
}

}

