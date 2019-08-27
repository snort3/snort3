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

#include <cassert>

#include "hash/lru_cache_shared.h"
#include "host_cache_interface.h"
#include "host_cache_allocator.h"
#include "host_tracker.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "sfip/sf_ip.h"
#include "utils/stats.h"

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

template<typename Key, typename Value, typename Hash>
class LruCacheSharedMemcap : public LruCacheShared<Key, Value, Hash>, public HostCacheInterface
{
public:
    using LruBase = LruCacheShared<Key, Value, Hash>;

    LruCacheSharedMemcap() = delete;
    LruCacheSharedMemcap(const LruCacheSharedMemcap& arg) = delete;
    LruCacheSharedMemcap& operator=(const LruCacheSharedMemcap& arg) = delete;

    LruCacheSharedMemcap(const size_t initial_size) : LruCacheShared<Key, Value, Hash>(initial_size) {}

    size_t mem_size() override
    {
        std::lock_guard<std::mutex> cache_lock(cache_mutex);
        return current_size;
    }

    void print_config()
    {
        if ( snort::SnortConfig::log_verbose() )
        {
            std::lock_guard<std::mutex> cache_lock(cache_mutex);

            snort::LogLabel("host_cache");
            snort::LogMessage("    memcap: %zu bytes\n", max_size);
        }

    }

    using Data = typename LruBase::Data;
    using ValueType = typename LruBase::ValueType;

    using LruBase::current_size;
    using LruBase::max_size;
    using LruBase::mem_chunk;
    using LruBase::cache_mutex;

    template <class T>
    friend class HostCacheAllocIp;

private:

    // Only the allocator calls this. The allocator, in turn, is called e.g.
    // from HostTracker::add_service(), which locks the host tracker
    // but not the cache. Therefore, update() must lock the cache.
    //
    // Note that any cache item object that is not yet owned by the cache
    // will increase / decrease the current_size of the cache any time it
    // adds / removes something to itself. Case in point: HostTracker.
    //
    // Therefore, if the cache items are containers that can grow dynamically,
    // then those items should be added to the cache first, and only accessed
    // via the cache. Then, any size change of the item, will legitimately
    // and correctly update the current_size of the cache.
    //
    // In concrete terms, never have a standalone HostTracker object outside
    // the host cache add or remove stuff to itself, as that will incorrectly
    // change the current_size of the cache.
    void update(int size) override
    {
        // Same idea as in LruCacheShared::remove(), use shared pointers
        // to hold the pruned data until after the cache is unlocked.
        // Do not change the order of data and cache_lock, as the data must
        // self destruct after cache_lock.
        std::list<Data> data;

        std::lock_guard<std::mutex> cache_lock(cache_mutex);

        if (size < 0)
            assert( current_size >= (size_t) -size );
        current_size += size;
        if (current_size > max_size)
            LruBase::prune(data);
    }

    // These get called only from within the LRU and assume the LRU is locked.
    void increase_size() override
    {
        current_size += mem_chunk;
    }

    void decrease_size() override
    {
        assert( current_size >= mem_chunk );
        current_size -= mem_chunk;
    }

};

typedef LruCacheSharedMemcap<snort::SfIp, snort::HostTracker, HashIp> HostCacheIp;

extern SO_PUBLIC HostCacheIp host_cache;

#endif
