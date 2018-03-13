//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <memory>

#include "hash/lru_cache_shared.h"
#include "host_tracker/host_tracker.h"

struct HostIpKey
{
    static const int key_size = 16;
    union host_ip_addr
    {
        uint8_t ip8[key_size];
        uint64_t ip64[key_size/8];
    } ip_addr = {{0}}; //  Holds either IPv4 or IPv6 addr

    HostIpKey() = default;

    HostIpKey(const uint8_t ip[key_size])
    {
        memcpy(&ip_addr, ip, key_size);
    }

    inline bool operator==(const HostIpKey& rhs) const
    {
        return !memcmp(&ip_addr, &rhs.ip_addr, key_size);
    }
};

//  Used to create hash of key for indexing into cache.
struct HashHostIpKey
{
    size_t operator()(const HostIpKey& ip) const
    {
        return std::hash<uint64_t>() (ip.ip_addr.ip64[0]) ^
               std::hash<uint64_t>() (ip.ip_addr.ip64[1]);
    }
};

extern LruCacheShared<HostIpKey, std::shared_ptr<HostTracker>, HashHostIpKey> host_cache;

void host_cache_add_host_tracker(HostTracker*);

namespace snort
{
//  Insert a new service into host cache if it doesn't already exist.
SO_PUBLIC bool host_cache_add_service(const SfIp&, Protocol, Port, const char* service);
}
#endif

