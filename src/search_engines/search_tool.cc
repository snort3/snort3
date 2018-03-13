//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "search_tool.h"

#include <cassert>

#include "managers/mpse_manager.h"

namespace snort
{
SearchTool::SearchTool(const char* method, bool dfa)
{
    mpse = MpseManager::get_search_engine(method);
    assert(mpse);
    max_len = 0;
    if( dfa )
        mpse->set_opt(1);
}

SearchTool::~SearchTool()
{
    MpseManager::delete_search_engine(mpse);
}

void SearchTool::add(const char* pat, unsigned len, int id, bool no_case)
{
    add((const uint8_t*)pat, len, id, no_case);
}

void SearchTool::add(const char* pat, unsigned len, void* id, bool no_case)
{
    add((const uint8_t*)pat, len, id, no_case);
}

void SearchTool::add(const uint8_t* pat, unsigned len, int id, bool no_case)
{
    add(pat, len, (void*)(long)id, no_case);
}

void SearchTool::add(const uint8_t* pat, unsigned len, void* id, bool no_case)
{
    Mpse::PatternDescriptor desc(no_case, false, true);

    if ( mpse )
        mpse->add_pattern(nullptr,  pat, len, desc, id);

    if ( len > max_len )
        max_len = len;
}

void SearchTool::prep()
{
    if ( mpse )
        mpse->prep_patterns(nullptr);
}

int SearchTool::find(
    const char* str,
    unsigned len,
    MpseMatch mf,
    int& state,
    bool confine,
    void* user_data)
{
    if ( confine && max_len > 0 )
    {
        if ( max_len < len )
            len = max_len;
    }
    if ( !user_data )
        user_data = (void*)str;

    int num = mpse->search((const uint8_t*)str, len, mf, user_data, &state);

    return num;
}

int SearchTool::find(
    const char* str,
    unsigned len,
    MpseMatch mf,
    bool confine,
    void* user_data)
{
    int state = 0;
    return find(str, len, mf, state, confine, user_data);
}

int SearchTool::find_all(
    const char* str,
    unsigned len,
    MpseMatch mf,
    bool confine,
    void* user_data)
{
    if ( confine && max_len > 0 )
    {
        if ( max_len < len )
            len = max_len;
    }
    if ( !user_data )
        user_data = (void*)str;

    int state = 0;

    int num = mpse->search_all((const uint8_t*)str, len, mf, user_data, &state);

    return num;
}
} // namespace snort
