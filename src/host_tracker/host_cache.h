//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

// host_cache.h author Steve Chew <stechew@cisco.com>

#ifndef HOST_CACHE_H
#define HOST_CACHE_H

// The host cache is used to cache information about hosts so that it can
// be shared among threads.

#include "hash/lru_cache_shared.h"
#include "host_tracker/host_tracker.h"
#include "sfip/sf_ip.h"

//  Used to create hash of key for indexing into cache.
struct HashIp
{
    size_t operator()(const snort::SfIp& ip) const
    {
        const uint64_t* ip64 = (const uint64_t*) ip.get_ip6_ptr();
        return std::hash<uint64_t>() (ip64[0]) ^
               std::hash<uint64_t>() (ip64[1]);
    }
};

extern SO_PUBLIC LruCacheShared<snort::SfIp, HostTracker, HashIp> host_cache;

#endif

