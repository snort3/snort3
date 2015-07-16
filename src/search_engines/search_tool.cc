//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "search_tool.h"

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "main/thread.h"
#include "framework/mpse.h"
#include "managers/mpse_manager.h"

SearchTool::SearchTool()
{
    mpse = MpseManager::get_search_engine("ac_bnfa");
    max_len = 0;
}

SearchTool::~SearchTool()
{
    MpseManager::delete_search_engine(mpse);
}

void SearchTool::add(const char* pat, unsigned len, int id, bool no_case)
{
    add((uint8_t*)pat, len, id, no_case);
}

void SearchTool::add(const uint8_t* pat, unsigned len, int id, bool no_case)
{
    if ( mpse )
        mpse->add_pattern(
            nullptr,  pat, len, no_case, false, (void*)(long)id, 0);

    if ( len > max_len )
        max_len = len;
}

void SearchTool::prep()
{
    if ( mpse )
        mpse->prep_patterns(nullptr, nullptr, nullptr);
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

    int num = mpse->search(
        (const unsigned char*)str, len, mf, user_data, &state);

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

    int num = mpse->search_all(
        (const unsigned char*)str, len, mf, user_data, &state);

    return num;
}

