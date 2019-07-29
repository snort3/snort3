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

// lru_cache_shared.h author Steve Chew <stechew@cisco.com>

#ifndef LRU_CACHE_SHARED_H
#define LRU_CACHE_SHARED_H

// LruCacheShared -- Implements a thread-safe unordered map where the
// least-recently-used (LRU) entries are removed once a fixed size is hit.

#include <list>
#include <memory>
#include <mutex>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#include "framework/counts.h"

extern const PegInfo lru_cache_shared_peg_names[];

struct LruCacheSharedStats
{
    PegCount adds = 0;       //  An insert that added new entry.
    PegCount prunes = 0;     //  When an old entry is removed to make
                             //  room for a new entry.
    PegCount find_hits = 0;  //  Found entry in cache.
    PegCount find_misses = 0; //  Did not find entry in cache.
};

template<typename Key, typename Value, typename Hash>
class LruCacheShared
{
public:
    //  Do not allow default constructor, copy constructor or assignment
    //  operator.  Cannot safely copy the LruCacheShared due to the mutex
    //  lock.
    LruCacheShared() = delete;
    LruCacheShared(const LruCacheShared& arg) = delete;
    LruCacheShared& operator=(const LruCacheShared& arg) = delete;

    LruCacheShared(const size_t initial_size) :
        max_size(initial_size), current_size(0) { }

    using Data = std::shared_ptr<Value>;

    // Return data entry associated with key. If doesn't exist, return nullptr.
    Data find(const Key& key);

    // Return data entry associated with key. If doesn't exist, create a new entry.
    Data operator[](const Key& key);

    // Return all data from the LruCache in order (most recently used to least)
    std::vector<std::pair<Key, Data> > get_all_data();

    //  Modify the maximum number of entries allowed in the cache.
    //  If the size is reduced, the oldest entries are removed.
    bool set_max_size(size_t newsize);

    const PegInfo* get_pegs() const
    {
        return lru_cache_shared_peg_names;
    }

    PegCount* get_counts()
    {
        return (PegCount*)&stats;
    }

    void lock()
    {
        cache_mutex.lock();
    }

    void unlock()
    {
        cache_mutex.unlock();
    }

private:
    using LruList = std::list<std::pair<Key, Data> >;
    using LruListIter = typename LruList::iterator;
    using LruMap  = std::unordered_map<Key, LruListIter, Hash>;
    using LruMapIter = typename LruMap::iterator;

    size_t max_size;   // Once max_size elements are in the cache, start to
                       // remove the least-recently-used elements.

    //  NOTE: std::list::size() is O(n) (it recounts the list every time)
    //        so instead we keep track of the current size manually.
    size_t current_size;    // Number of entries currently in the cache.

    std::mutex cache_mutex;
    LruList list;  //  Contains key/data pairs. Maintains LRU order with
                   //  least recently used at the end.
    LruMap map;    //  Maps key to list iterator for fast lookup.

    struct LruCacheSharedStats stats;
};

template<typename Key, typename Value, typename Hash>
bool LruCacheShared<Key, Value, Hash>::set_max_size(size_t newsize)
{
    LruListIter list_iter;

    if (newsize == 0)
        return false;   //  Not allowed to set size to zero.

    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    //  Remove the oldest entries if we have to reduce cache size.
    while (current_size > newsize)
    {
        list_iter = list.end();
        --list_iter;
        current_size--;
        map.erase(list_iter->first);
        list.erase(list_iter);
        stats.prunes++;
    }

    max_size = newsize;
    return true;
}

template<typename Key, typename Value, typename Hash>
std::shared_ptr<Value> LruCacheShared<Key, Value, Hash>::find(const Key& key)
{
    LruMapIter map_iter;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter == map.end())
    {
        stats.find_misses++;
        return nullptr;
    }

    //  Move entry to front of LruList
    list.splice(list.begin(), list, map_iter->second);
    stats.find_hits++;
    return map_iter->second->second;
}

template<typename Key, typename Value, typename Hash>
std::shared_ptr<Value> LruCacheShared<Key, Value, Hash>::operator[](const Key& key)
{
    LruMapIter map_iter;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter != map.end())
    {
        stats.find_hits++;
        list.splice(list.begin(), list, map_iter->second); // update LRU
        return map_iter->second->second;
    }

    stats.find_misses++;
    stats.adds++;
    Data data = Data(new Value);

    //  Add key/data pair to front of list.
    list.emplace_front(std::make_pair(key, data));

    //  Add list iterator for the new entry to map.
    map[key] = list.begin();

    //  If we've exceeded the configured size, remove the oldest entry.
    if (current_size >= max_size)
    {
        LruListIter list_iter;
        list_iter = list.end();
        --list_iter;
        map.erase(list_iter->first);
        list.erase(list_iter);
        stats.prunes++;
    }
    else
    {
        current_size++;
    }
    return data;
}

template<typename Key, typename Value, typename Hash>
std::vector< std::pair<Key, std::shared_ptr<Value>> >
LruCacheShared<Key, Value, Hash>::get_all_data()
{
    std::vector<std::pair<Key, Data> > vec;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    for (auto& entry : list )
    {
        vec.emplace_back(entry);
    }

    return vec;
}

#endif

