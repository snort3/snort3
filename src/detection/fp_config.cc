//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

// fp_config.cc is derived from fpcreate.cc by:
/*
**  Dan Roelker <droelker@sourcefire.com>
**  Marc Norton <mnorton@sourcefire.com>
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fp_config.h"

#include <cassert>
#include <cstring>

#include "framework/mpse.h"
#include "log/messages.h"
#include "managers/mpse_manager.h"

using namespace snort;

FastPatternConfig::FastPatternConfig()
{
    search_api = MpseManager::get_search_api("ac_bnfa");
    assert(search_api);
}


bool FastPatternConfig::set_search_method(const char* method)
{
    const MpseApi* api = MpseManager::get_search_api(method);

    if ( !api )
        return false;

    search_api = api;

    // FIXIT-L query search_api capabilities when API is redone
    // same for offload
    if ( !strcmp(method, "hyperscan") )
        dedup = false;

    return true;
}

const char* FastPatternConfig::get_search_method() const
{
    if ( !search_api )
        return nullptr;

    return search_api->base.name;
}

bool FastPatternConfig::set_offload_search_method(const char* method)
{
    const MpseApi* api = MpseManager::get_search_api(method);

    if ( !api )
        return false;

    offload_search_api = api;

    if ( !dedup and !strcmp(method, "hyperscan") )
        dedup = false;

    return true;
}

void FastPatternConfig::set_max_pattern_len(unsigned int max_len)
{
    max_pattern_len = max_len;
}

unsigned FastPatternConfig::set_max(unsigned bytes)
{
    if ( max_pattern_len and (bytes > max_pattern_len) )
    {
        bytes = max_pattern_len;
        num_patterns_truncated++;
    }
    return bytes;
}

void FastPatternConfig::set_queue_limit(unsigned int limit)
{
    queue_limit = limit;
}

