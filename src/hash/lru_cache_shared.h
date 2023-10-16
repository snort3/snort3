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

// lru_cache_shared.h author Steve Chew <stechew@cisco.com>

#ifndef LRU_CACHE_SHARED_H
#define LRU_CACHE_SHARED_H

// LruCacheShared -- Implements a thread-safe unordered map where the
// least-recently-used (LRU) entries are removed once a fixed size is hit.

#include <atomic>
#include <cassert>
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
    PegCount adds = 0;          // an insert that added new entry
    PegCount alloc_prunes = 0;  // when an old entry is removed to make room for a new entry
    PegCount bytes_in_use = 0;  // current bytes in use
    PegCount items_in_use = 0;  // current items in cache
    PegCount find_hits = 0;     // found entry in cache
    PegCount find_misses = 0;   // did not find entry in cache
    PegCount reload_prunes = 0; // when an old entry is removed due to lower memcap during reload
    PegCount removes = 0;       // found entry and removed it
    PegCount replaced = 0;      // found entry and replaced it
};

enum class LcsInsertStatus {
    LCS_ITEM_PRESENT,
    LCS_ITEM_INSERTED,
    LCS_ITEM_REPLACED
};

template<typename Key, typename Value, typename Hash, typename Eq = std::equal_to<Key>,
    typename Purgatory = std::vector<std::shared_ptr<Value>>>
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

    virtual ~LruCacheShared() = default;

    using Data = std::shared_ptr<Value>;
    using ValueType = Value;
    using KeyType = Key;

    // Return data entry associated with key. If doesn't exist, return nullptr.
    Data find(const Key& key);

    // Return data entry associated with key. If doesn't exist, create a new entry.
    Data operator[](const Key& key);

    // Same as operator[]; additionally, sets the boolean if a new entry is created.
    Data find_else_create(const Key& key, bool* new_data);

    // Returns true if found or replaced, takes a ref to a user managed entry
    bool find_else_insert(const Key& key, std::shared_ptr<Value>& data, bool replace = false);

    // Returns the found or inserted data, takes a ref to user managed entry.
    Data find_else_insert(const Key&, Data&, LcsInsertStatus*, bool = false);

    // Return all data from the LruCache in order (most recently used to least)
    std::vector<std::pair<Key, Data> > get_all_data();

    //  Get current number of elements in the LruCache.
    size_t size()
    {
        std::lock_guard<std::mutex> cache_lock(cache_mutex);
        return list.size();
    }

    virtual size_t mem_size()
    {
        std::lock_guard<std::mutex> cache_lock(cache_mutex);
        return list.size() * mem_chunk;
    }

    size_t get_max_size()
    {
        return max_size;
    }

    //  Modify the maximum number of entries allowed in the cache. If the size is reduced,
    //  the oldest entries are removed. This pruning doesn't utilize reload resource tuner.
    bool set_max_size(size_t newsize);

    //  Remove entry associated with Key.
    //  Returns true if entry existed, false otherwise.
    virtual bool remove(const Key& key);

    //  Remove entry associated with key and return removed data.
    //  Returns true and copy of data if entry existed.  Returns false if
    //  entry did not exist.
    virtual bool remove(const Key& key, Data& data);

    const PegInfo* get_pegs() const
    { return lru_cache_shared_peg_names; }

    PegCount* get_counts()
    { return (PegCount*)&stats; }

    void lock()
    { cache_mutex.lock(); }

    void unlock()
    { cache_mutex.unlock(); }

protected:
    using LruList = std::list<std::pair<Key, Data>>;
    using LruListIter = typename LruList::iterator;
    using LruMap = std::unordered_map<Key, LruListIter, Hash, Eq>;
    using LruMapIter = typename LruMap::iterator;

    static constexpr size_t mem_chunk = sizeof(Data) + sizeof(Value);

    std::atomic<size_t> max_size; // Once max_size elements are in the cache, start to
                                  // remove the least-recently-used elements.

    std::atomic<size_t> current_size;// Number of entries currently in the cache.

    std::mutex cache_mutex;
    LruList list;  //  Contains key/data pairs. Maintains LRU order with
                   //  least recently used at the end.
    LruMap map;    //  Maps key to list iterator for fast lookup.

    struct LruCacheSharedStats stats;

    // The reason for these functions is to allow derived classes to do their
    // size book keeping differently (e.g. host_cache). This effectively
    // decouples the current_size variable from the actual size in memory,
    // so these functions should only be called when something is actually
    // added or removed from memory (e.g. in find_else_insert, remove, etc).
    virtual void increase_size(ValueType* value_ptr=nullptr)
    {
        UNUSED(value_ptr);
        current_size++;
    }

    virtual void decrease_size(ValueType* value_ptr=nullptr)
    {
        UNUSED(value_ptr);
        current_size--;
    }

    // Caller must lock and unlock. Don't use this during snort reload for which
    // we need gradual pruning and size reduction via reload resource tuner.
    void prune(Purgatory& data)
    {
        LruListIter list_iter;
        assert(data.empty());
        while (current_size > max_size && !list.empty())
        {
            list_iter = --list.end();
            data.emplace_back(list_iter->second); // increase reference count
            decrease_size(list_iter->second.get());
            map.erase(list_iter->first);
            list.erase(list_iter);
            ++stats.alloc_prunes;
        }
    }
};

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
bool LruCacheShared<Key, Value, Hash, Eq, Purgatory>::set_max_size(size_t newsize)
{
    if (newsize == 0)
        return false;   //  Not allowed to set size to zero.

    // Like with remove(), we need local temporary references to data being
    // deleted, to avoid race condition. This data needs to self-destruct
    // after the cache_lock does.
    Purgatory data;

    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    //  Remove the oldest entries if we have to reduce cache size.
    max_size = newsize;

    prune(data);

    return true;
}

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
std::shared_ptr<Value> LruCacheShared<Key, Value, Hash, Eq, Purgatory>::find(const Key& key)
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

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
std::shared_ptr<Value> LruCacheShared<Key, Value, Hash, Eq, Purgatory>::operator[](const Key& key)
{
    return find_else_create(key, nullptr);
}

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
std::shared_ptr<Value> LruCacheShared<Key, Value, Hash, Eq, Purgatory>::
find_else_create(const Key& key, bool* new_data)
{
    LruMapIter map_iter;

    // As with remove and operator[], we need a temporary list of references
    // to delay the destruction of the items being removed by prune().
    // This is one instance where we cannot get by with directly locking and
    // unlocking the cache_mutex, because the cache must be locked when we
    // return the data pointer (below), or else, some other thread might
    // delete it before we got a chance to return it.
    Purgatory tmp_data;

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
    if ( new_data )
        *new_data = true;
    Data data = Data(new Value);

    //  Add key/data pair to front of list.
    list.emplace_front(std::make_pair(key, data));
    increase_size(data.get());

    //  Add list iterator for the new entry to map.
    map[key] = list.begin();

    prune(tmp_data);

    return data;
}

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
bool LruCacheShared<Key, Value, Hash, Eq, Purgatory>::
find_else_insert(const Key& key, std::shared_ptr<Value>& data, bool replace)
{
    LruMapIter map_iter;

    Purgatory tmp_data;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter != map.end())
    {
        stats.find_hits++;
        if (replace)
        {
            // Explicitly calling the reset so its more clear that destructor could be called for the object
            decrease_size(map_iter->second->second.get());
            map_iter->second->second.reset();
            map_iter->second->second = data;
            increase_size(map_iter->second->second.get());
            stats.replaced++;
        }
        list.splice(list.begin(), list, map_iter->second); // update LRU
        return true;
    }

    stats.find_misses++;
    stats.adds++;

    //  Add key/data pair to front of list.
    list.emplace_front(std::make_pair(key, data));
    increase_size(data.get());

    //  Add list iterator for the new entry to map.
    map[key] = list.begin();

    prune(tmp_data);

    return false;
}

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
std::shared_ptr<Value> LruCacheShared<Key, Value, Hash, Eq, Purgatory>::
find_else_insert(const Key& key, std::shared_ptr<Value>& data, LcsInsertStatus* status, bool replace)
{
    LruMapIter map_iter;

    Purgatory tmp_data;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter != map.end())
    {
        stats.find_hits++;
        if (status) *status = LcsInsertStatus::LCS_ITEM_PRESENT;
        if (replace)
        {
            // Explicitly calling the reset so its more clear that destructor could be called for the object
            decrease_size(map_iter->second->second.get());
            map_iter->second->second.reset();
            map_iter->second->second = data;
            increase_size(map_iter->second->second.get());
            stats.replaced++;
            if (status) *status = LcsInsertStatus::LCS_ITEM_REPLACED;
        }
        list.splice(list.begin(), list, map_iter->second); // update LRU
        return map_iter->second->second;
    }

    stats.find_misses++;
    stats.adds++;
    if (status) *status = LcsInsertStatus::LCS_ITEM_INSERTED;

    //  Add key/data pair to front of list.
    list.emplace_front(std::make_pair(key, data));
    increase_size(data.get());

    //  Add list iterator for the new entry to map.
    map[key] = list.begin();

    prune(tmp_data);

    return data;
}

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
std::vector< std::pair<Key, std::shared_ptr<Value>> >
LruCacheShared<Key, Value, Hash, Eq, Purgatory>::get_all_data()
{
    std::vector<std::pair<Key, Data> > vec;
    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    for (auto& entry : list )
    {
        vec.emplace_back(entry);
    }

    return vec;
}

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
bool LruCacheShared<Key, Value, Hash, Eq, Purgatory>::remove(const Key& key)
{
    LruMapIter map_iter;

    // There is a potential race condition here, when the destructor of
    // the object being removed needs to call back into the cache and lock
    // the cache (e.g. via an allocator) to update the size of the cache.
    //
    // The shared pointer below fixes this condition by increasing the
    // reference count to the object being deleted, thus delaying the
    // call to the destructor until after the cache is unlocked.
    //
    // In particular, since the cache must be unlocked when data self-destructs
    // data must be defined before cache_lock. Do not change the order of
    // data and cache_lock!
    Data data;

    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter == map.end())
    {
        return false;   //  Key is not in LruCache.
    }

    data = map_iter->second->second;

    decrease_size(data.get());
    list.erase(map_iter->second);
    map.erase(map_iter);
    stats.removes++;

    assert( data.use_count() > 0 );

    // Now, data can go out of scope and if it needs to lock again while
    // deleting the Value object, it can do so.

    return true;
}

template<typename Key, typename Value, typename Hash, typename Eq, typename Purgatory>
bool LruCacheShared<Key, Value, Hash, Eq, Purgatory>::remove(const Key& key,
    std::shared_ptr<Value>& data)
{
    LruMapIter map_iter;

    std::lock_guard<std::mutex> cache_lock(cache_mutex);

    map_iter = map.find(key);
    if (map_iter == map.end())
    {
        return false;   //  Key is not in LruCache.
    }

    data = map_iter->second->second;

    decrease_size(data.get());
    list.erase(map_iter->second);
    map.erase(map_iter);
    stats.removes++;

    assert( data.use_count() > 0 );

    return true;
}

#endif
