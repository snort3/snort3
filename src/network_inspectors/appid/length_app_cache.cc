//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// length_app_cache.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "length_app_cache.h"

#include <map>

#include "log/messages.h"
#include "main/thread.h"

#include "application_ids.h"

using namespace snort;

static std::map<LengthKey, AppId>* length_cache = nullptr;

void init_length_app_cache()
{
    length_cache = new std::map<LengthKey, AppId>;
}

void free_length_app_cache()
{
    delete length_cache;
    length_cache = nullptr;
}

AppId find_length_app_cache(const LengthKey& key)
{
    auto entry = length_cache->find(key);
    if (entry == length_cache->end())
        return APP_ID_NONE;    /* no match */
    else
        return entry->second;  /* match found */
}

bool add_length_app_cache(const LengthKey& key, AppId val)
{
    return (length_cache->insert(std::make_pair(key, val))).second == true;
}

