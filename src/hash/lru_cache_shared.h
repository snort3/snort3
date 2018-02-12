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

// lru_cache_shared.h author Steve Chew <stechew@cisco.com>

#ifndef LRU_CACHE_SHARED_H
#define LRU_CACHE_SHARED_H

// LruCacheShared -- Implements a thread-safe unordered map where the
// least-recently-used (LRU) entries are removed once a fixed size is hit.

#include <list>
#include <vector>
#include <unordered_map>
#include <mutex>

#include "framework/counts.h"

extern const PegInfo lru_cache_shared_peg_names[];

struct LruCacheSharedStats
{
    PegCount adds = 0;       //  An insert that added new entry.
    PegCount replaces = 0;   //  An insert that replaced existing entry
    PegCount prunes = 0;     //  When an old entry is removed to make
                             //  room for a new entry.
    PegCount find_hits = 0;  //  Found entry in cache.
    PegCount find_misses = 0; //  Did not find entry in cache.
    PegCount removes = 0;    //  Found entry and removed it.
    PegCount clears = 0;     //  Calls to clear API.
};

template<typename Key, typename Data, typename Hash>
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
        max_size(initial_size),
        current_size(0)
    {
    }

    //  Get current number of elements in the LruCache.
    size_t size()
    {
        std::lock_guard<std::mutex> cache_lock(cache_mutex);
        return current_size;
    }

    size_t get_max_size()
    {
        std::lock_guard<std::mutex> cache_lock(cache_mutex);
        return max_size;
    }

    //  Modify the maximum number of entries allowed in the cache.
    //  If the size is reduced, the oldest entries are removed.
    bool set_max_size(size_t newsize);

    //  Add data to cache or replace data if it already exists.
    void insert(const Key& key, const Data& data);

    //  Find Data associated with Key.  If update is true, mark entry as
    //  recently used.
    //  Returns true and copies data if the key is found.
    bool find(const Key& key, Data& data, bool update=true);

    //  Remove entry associated with Key.
    //  Returns true if entry existed, false otherwise.
    bool remove(const Key& key);

    //  Remove entry associated with key and return removed data.
    //  Returns true and copy of data if entry existed.  Returns false if
    //  entry did not exist.
    bool remove(const Key& key, Data& data);

    //  Remove all elements from the LruCache
    void clear();

    //  Return all data from the LruCache in order (most recently used to
    //  least).
    std::vector<std::pair<Key, Data> > get_all_data();

    const PegInfo* get_pegs() const
    {
        return lru_cache_shared_peg_names;
    }

    PegCount* get_counts() const
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

template<typename Key, typename Data, typename Hash>
bool LruCacheShared<Key, Data, Hash>::set_max_size(size_t newsize)
{
    LruListIter list_iter;

    if (newsize <= 0)
        return false;   //  Not allowed to set size to zero.

    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    //  Remove the oldest entries if we have to reduce cache size.
    list_iter=list.end();
    while (current_size > newsize)
    {
        --list_iter;
        current_size--;
        map.erase(list_iter->first);
        list.erase(list_iter);
    }

    max_size = newsize;
    return true;
}

template<typename Key, typename Data, typename Hash>
void LruCacheShared<Key, Data, Hash>::insert(const Key& key, const Data& data)
{
    LruMapIter map_iter;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    //  If key already exists, remove it.
    map_iter = map.find(key);
    if (map_iter != map.end())
    {
        current_size--;
        list.erase(map_iter->second);
        map.erase(map_iter);
        stats.replaces++;
    }
    else
    {
        stats.adds++;
    }

    //  Add key/data pair to front of list.
    list.push_front(std::make_pair(key, data));

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
}

template<typename Key, typename Data, typename Hash>
bool LruCacheShared<Key, Data, Hash>::find(const Key& key, Data& data, bool update)
{
    LruMapIter map_iter;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter == map.end())
    {
        stats.find_misses++;
        return false;   //  Key is not in LruCache.
    }

    data = map_iter->second->second;

    //  If needed, move entry to front of LruList
    if (update)
        list.splice(list.begin(), list, map_iter->second);

    stats.find_hits++;
    return true;
}

template<typename Key, typename Data, typename Hash>
bool LruCacheShared<Key, Data, Hash>::remove(const Key& key)
{
    LruMapIter map_iter;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter == map.end())
        return false;   //  Key is not in LruCache.

    current_size--;
    list.erase(map_iter->second);
    map.erase(map_iter);
    stats.removes++;
    return(true);
}

template<typename Key, typename Data, typename Hash>
bool LruCacheShared<Key, Data, Hash>::remove(const Key& key, Data& data)
{
    LruMapIter map_iter;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter == map.end())
        return false;   //  Key is not in LruCache.

    data = map_iter->second->second;

    current_size--;
    list.erase(map_iter->second);
    map.erase(map_iter);
    stats.removes++;
    return(true);
}

template<typename Key, typename Data, typename Hash>
void LruCacheShared<Key, Data, Hash>::clear()
{
    LruMapIter map_iter;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    for (map_iter = map.begin(); map_iter != map.end(); /* No incr */)
    {
        list.erase(map_iter->second);

        //  erase returns next iterator after erased element.
        map_iter = map.erase(map_iter);
    }

    current_size = 0;
    stats.clears++;
}

template<typename Key, typename Data, typename Hash>
std::vector<std::pair<Key, Data> > LruCacheShared<Key, Data, Hash>::get_all_data()
{
    std::vector<std::pair<Key, Data> > vec;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    for (auto& entry : list )
    {
        vec.push_back(entry);
    }

    return vec;
}

#endif

