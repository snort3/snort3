//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// lru_cache_shared.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/lru_cache_shared.h"

const PegInfo lru_cache_shared_peg_names[] =
{
    { CountType::SUM, "adds", "lru cache added new entry" },
    { CountType::SUM, "alloc_prunes", "lru cache pruned entry to make space for new entry" },
    { CountType::NOW, "bytes_in_use", "current number of bytes in use" },
    { CountType::NOW, "items_in_use", "current number of items in the cache" },
    { CountType::SUM, "find_hits", "lru cache found entry in cache" },
    { CountType::SUM, "find_misses", "lru cache did not find entry in cache" },
    { CountType::SUM, "reload_prunes", "lru cache pruned entry for lower memcap during reload" },
    { CountType::SUM, "removes", "lru cache found entry and removed it" },
    { CountType::SUM, "replaced", "lru cache found entry and replaced it" },
    { CountType::END, nullptr, nullptr },
};
