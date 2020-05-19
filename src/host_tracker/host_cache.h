//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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
    using LruBase::cache_mutex;
    using LruBase::current_size;
    using LruBase::list;
    using LruBase::map;
    using LruBase::max_size;
    using LruBase::mem_chunk;
    using LruBase::stats;
    using Data = typename LruBase::Data;
    using LruListIter = typename LruBase::LruListIter;
    using ValueType = typename LruBase::ValueType;

    LruCacheSharedMemcap() = delete;
    LruCacheSharedMemcap(const LruCacheSharedMemcap& arg) = delete;
    LruCacheSharedMemcap& operator=(const LruCacheSharedMemcap& arg) = delete;

    LruCacheSharedMemcap(const size_t initial_size) : LruCacheShared<Key, Value, Hash>(initial_size) {}

    size_t mem_size() override
    {
        return current_size;
    }

    void print_config()
    {
        if ( snort::SnortConfig::get_conf()->log_verbose() )
        {
            std::lock_guard<std::mutex> cache_lock(cache_mutex);

            snort::LogLabel("host_cache");
            snort::LogMessage("    memcap: %zu bytes\n", max_size);
        }

    }

    // If the new memcap causes pruning, don't modify max_size and return true signifying that
    // a gradual pruning/resizing is needed. Otherwise, modify max_size and return false.
    bool reload_resize(size_t new_size)
    {
        if ( current_size > new_size )
            return true;

        std::lock_guard<std::mutex> cache_lock(cache_mutex);
        max_size = new_size;
        return false;
    }

    // Prune a few entries at each call and set the max_size to the current watermark.
    // Return true when the desired memcap is reached.
    bool reload_prune(size_t new_size, unsigned max_prune)
    {
        std::unique_lock<std::mutex> reload_lock(reload_mutex, std::try_to_lock);
        if ( !reload_lock.owns_lock() )
            return false; // some other thread wins this round

        // Since decrease_size() does not account associated objects in host_tracker,
        // we may over-prune if we remove max_prune entries in a single attempt. Instead,
        // we acquire lock, hold data, release lock, and delete data in each iteration.
        while ( max_prune-- > 0 )
        {
            // Get a local temporary reference of data being deleted (as if a trash can).
            // To avoid race condition, data needs to self-destruct after the cache_lock does.
            Data data;
            std::lock_guard<std::mutex> cache_lock(cache_mutex);

            if ( !list.empty() )
            {
                // A data race when reload changes max_size while other threads read this may
                // delay pruning by one round. Yet, we are avoiding mutex for better performance.
                max_size = current_size;
                if ( max_size > new_size )
                {
                    LruListIter list_iter = --list.end();
                    data = list_iter->second; // increase reference count
                    decrease_size();
                    max_size -= mem_chunk; // in sync with current_size
                    map.erase(list_iter->first);
                    list.erase(list_iter);
                    ++stats.reload_prunes;
                }
            }

            if ( max_size <= new_size or list.empty() )
            {
                max_size = new_size;
                return true;
            }
        }

        return false;
    }

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
        if ( size < 0 )
        {
            assert( current_size >= (size_t) -size);
        }
        if ( (current_size += size) > max_size )
        {
            // Same idea as in LruCacheShared::remove(), use shared pointers
            // to hold the pruned data until after the cache is unlocked.
            // Do not change the order of data and cache_lock, as the data must
            // self destruct after cache_lock.
            std::vector<Data> data;
            std::lock_guard<std::mutex> cache_lock(cache_mutex);
            LruBase::prune(data);
        }
    }

    void increase_size() override
    {
        current_size += mem_chunk;
    }

    void decrease_size() override
    {
        assert( current_size >= mem_chunk );
        current_size -= mem_chunk;
    }

    std::mutex reload_mutex;
    friend class TEST_host_cache_module_misc_Test; // for unit test
};

typedef LruCacheSharedMemcap<snort::SfIp, snort::HostTracker, HashIp> HostCacheIp;

extern SO_PUBLIC HostCacheIp host_cache;

#endif
