//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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

// lru_cache_local.h author Masud Hasan <mashasan@cisco.com>

#ifndef LRU_CACHE_LOCAL_H
#define LRU_CACHE_LOCAL_H

// LruCacheLocal - A simple thread-unsafe memcap-enforced least-recently-used cache.

#include <list>
#include <unordered_map>
#include <vector>

#include "framework/counts.h"

#define LRU_CACHE_LOCAL_PEGS(module) \
    { CountType::SUM, "cache_adds", module " cache added new entry" }, \
    { CountType::SUM, "cache_hits", module " cache found existing entry" }, \
    { CountType::SUM, "cache_misses", module " cache did not find entry" }, \
    { CountType::SUM, "cache_replaces", module " cache found entry and replaced its value" }, \
    { CountType::SUM, "cache_max", module " cache's maximum byte usage"}, \
    { CountType::SUM, "cache_prunes", module " cache pruned entry to make space for new entry" }, \
    { CountType::SUM, "cache_removes", module " cache removed existing entry"}

struct LruCacheLocalStats
{
    PegCount cache_adds;
    PegCount cache_hits;
    PegCount cache_misses;
    PegCount cache_replaces;
    PegCount cache_max;
    PegCount cache_prunes;
    PegCount cache_removes;
};

template<typename Key, typename Value, typename Hash>
class LruCacheLocal
{
public:
    LruCacheLocal(const size_t sz, struct LruCacheLocalStats& st)
        : max_size(sz), current_size(0), stats(st) { }

    virtual ~LruCacheLocal() = default;

    // Return 1 if an entry associated with the key exists, else return 0
    int count(const Key&);

    // Return the entry associated with the key; insert new entry if absent
    Value& find_else_create(const Key&, bool* is_new = nullptr);

    // If key does not exist, insert the key-value pair and return true;
    // else return false replacing the existing value if asked
    bool add(const Key&, const Value&, bool replace = false);

    // If key does not exist, return false;
    // else remove the entry associated with key
    bool remove(const Key&);

    // Copy all key-value pairs from the cache
    void get_all_values(std::vector<std::pair<Key, Value>>&);

protected:
    using LruList = std::list<std::pair<Key, Value>>;
    using LruListIter = typename LruList::iterator;
    using LruMap = std::unordered_map<Key, LruListIter, Hash>;
    using LruMapIter = typename LruMap::iterator;

    void prune();
    void add_entry(const Key&, const Value&);

    static constexpr size_t entry_size = 2 * sizeof(Key) + sizeof(Value) + sizeof(LruListIter);
    const size_t max_size;
    size_t current_size;
    LruList list;
    LruMap map;
    struct LruCacheLocalStats& stats;
};

template<typename Key, typename Value, typename Hash>
void LruCacheLocal<Key, Value, Hash>::prune()
{
    if ( !max_size )
        return;

    while ( current_size > max_size and !list.empty() )
    {
        auto it = --list.end();
        map.erase(it->first);
        list.erase(it);
        current_size -= entry_size;
        ++stats.cache_prunes;
    }
}

template<typename Key, typename Value, typename Hash>
int LruCacheLocal<Key, Value, Hash>::count(const Key& key)
{
    return map.count(key);
}

template<typename Key, typename Value, typename Hash>
void LruCacheLocal<Key, Value, Hash>::add_entry(const Key& key, const Value& value)
{
    stats.cache_adds++;
    list.emplace_front(std::make_pair(key, value));
    map[key] = list.begin();
    current_size += entry_size;
    prune();
    if ( stats.cache_max < current_size )
        stats.cache_max = current_size;
}

template<typename Key, typename Value, typename Hash>
Value& LruCacheLocal<Key, Value, Hash>::find_else_create(const Key& key, bool* is_new)
{
    auto it = map.find(key);
    if (it == map.end())
    {
        stats.cache_misses++;
        add_entry(key, Value());
        if ( is_new )
            *is_new = true;
        return list.begin()->second;
    }

    stats.cache_hits++;
    list.splice(list.begin(), list, it->second);
    return list.begin()->second;
}

template<typename Key, typename Value, typename Hash>
bool LruCacheLocal<Key, Value, Hash>::add(const Key& key, const Value& value, bool replace)
{
    auto it = map.find(key);
    if (it == map.end())
    {
        stats.cache_misses++;
        add_entry(key, value);
        return true;
    }

    stats.cache_hits++;
    list.splice(list.begin(), list, it->second);
    if ( replace )
    {
        it->second->second = value;
        stats.cache_replaces++;
    }
    return false;
}

template<typename Key, typename Value, typename Hash>
bool LruCacheLocal<Key, Value, Hash>::remove(const Key& key)
{
    auto it = map.find(key);
    if (it == map.end())
    {
        return false;
    }
    list.erase(it->second);
    map.erase(it);
    current_size -= entry_size;
    stats.cache_removes++;
    return true;
}

template<typename Key, typename Value, typename Hash>
void LruCacheLocal<Key, Value, Hash>::get_all_values(std::vector<std::pair<Key, Value>>& kv)
{
    for (auto& entry : list )
        kv.emplace_back(entry);
}

#endif
