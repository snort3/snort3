//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
// search_tool.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <cstring>

#include "detection/fp_config.h"
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "main/snort_config.h"
#include "search_tool.h"

namespace snort
{
SearchTool::SearchTool(bool multi, const char* override_method)
{
    const SnortConfig* sc = SnortConfig::get_conf();
    assert(sc and sc->fast_pattern_config);
    assert(!override_method || strcmp(override_method, "hyperscan"));
    const char* method = override_method ? override_method : sc->fast_pattern_config->get_search_method();

    if ( strcmp(method, "hyperscan") )
        method = "ac_full";

    mpsegrp = new MpseGroup;
    mpsegrp->create_normal_mpse(sc, method);
    assert(mpsegrp->get_normal_mpse());

    multi_match = multi;
    max_len = 0;
}

SearchTool::~SearchTool()
{
    delete mpsegrp;
}

const char* SearchTool::get_method() const
{ return mpsegrp->get_normal_mpse()->get_method(); }

void SearchTool::add(const char* pat, unsigned len, int id, bool no_case, bool literal)
{ add((const uint8_t*)pat, len, id, no_case, literal); }

void SearchTool::add(const char* pat, unsigned len, void* id, bool no_case, bool literal)
{ add((const uint8_t*)pat, len, id, no_case, literal); }

void SearchTool::add(const uint8_t* pat, unsigned len, int id, bool no_case, bool literal)
{ add(pat, len, (void*)(long)id, no_case, literal); }

void SearchTool::add(const uint8_t* pat, unsigned len, void* id, bool no_case, bool literal)
{
    Mpse::PatternDescriptor desc(no_case, false, literal, multi_match);

    if ( mpsegrp->normal_mpse )
        mpsegrp->normal_mpse->add_pattern(pat, len, desc, id);

    if ( mpsegrp->offload_mpse )
        mpsegrp->offload_mpse->add_pattern(pat, len, desc, id);

    if ( len > max_len )
        max_len = len;
}

void SearchTool::prep()
{
    if ( mpsegrp->normal_mpse )
        mpsegrp->normal_mpse->prep_patterns(nullptr);
    if ( mpsegrp->offload_mpse )
        mpsegrp->offload_mpse->prep_patterns(nullptr);
}

void SearchTool::reload()
{
    if ( mpsegrp->normal_mpse )
        mpsegrp->normal_mpse->reuse_search();
    if ( mpsegrp->offload_mpse )
        mpsegrp->offload_mpse->reuse_search();
}

int SearchTool::find(
    const char* str, unsigned len, MpseMatch mf, int& state, bool confine, void* user_data)
{
    int num = 0;
    const SnortConfig* sc = SnortConfig::get_conf();
    const FastPatternConfig* fp = sc->fast_pattern_config;

    if ( confine && max_len > 0 )
    {
        if ( max_len < len )
            len = max_len;
    }
    if ( !user_data )
        user_data = (void*)str;

    if ( fp and fp->get_offload_search_api() and (len >= sc->offload_limit) and
        (mpsegrp->get_offload_mpse() != mpsegrp->get_normal_mpse()) )
    {
        num = mpsegrp->get_offload_mpse()->search((const uint8_t*)str, len, mf, user_data, &state);

        if ( num < 0 )
            num = mpsegrp->get_normal_mpse()->search((const uint8_t*)str, len, mf, user_data, &state);
    }
    else
        num = mpsegrp->get_normal_mpse()->search((const uint8_t*)str, len, mf, user_data, &state);

    // SeachTool::find expects the number found to be returned so if we have a failure return 0
    if ( num < 0 )
        num = 0;

    return num;
}

int SearchTool::find(
    const char* str, unsigned len, MpseMatch mf, bool confine, void* user_data)
{
    int state = 0;
    return find(str, len, mf, state, confine, user_data);
}

int SearchTool::find_all(
    const char* str, unsigned len, MpseMatch mf, bool confine, void* user_data, const SnortConfig* sc)
{
    int num = 0;
    if (!sc)
        sc = SnortConfig::get_conf();
    const FastPatternConfig* fp = sc ? sc->fast_pattern_config : nullptr;

    if ( confine && max_len > 0 )
    {
        if ( max_len < len )
            len = max_len;
    }
    if ( !user_data )
        user_data = (void*)str;

    int state = 0;

    if ( fp and fp->get_offload_search_api() and (len >= sc->offload_limit) and
        (mpsegrp->get_offload_mpse() != mpsegrp->get_normal_mpse()) )
    {
        num = mpsegrp->get_offload_mpse()->search_all((const uint8_t*)str, len, mf, user_data, &state);

        if ( num < 0 )
            num = mpsegrp->get_normal_mpse()->search_all((const uint8_t*)str, len, mf, user_data, &state);
    }
    else
        num = mpsegrp->get_normal_mpse()->search_all((const uint8_t*)str, len, mf, user_data, &state);

    // SeachTool::find expects the number found to be returned so if we have a failure return 0
    if ( num < 0 )
        num = 0;

    return num;
}
} // namespace snort

