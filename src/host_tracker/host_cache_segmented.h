//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// host_cache_segmented.h author Raza Shafiq <rshafiq@cisco.com>

#ifndef HOST_CACHE_SEGMENTED_H
#define HOST_CACHE_SEGMENTED_H

#include <atomic>
#include <cassert>
#include <numeric>

#include "host_cache.h"
#include "log/log_stats.h"
#include "log/messages.h"

#define DEFAULT_HOST_CACHE_SEGMENTS 4

extern SO_PUBLIC HostCacheIp default_host_cache;
extern THREAD_LOCAL struct LruCacheSharedStats host_cache_counts;

template<typename Key, typename Value>
class HostCacheSegmented
{
public:
    HostCacheSegmented() :
        segment_count(DEFAULT_HOST_CACHE_SEGMENTS),
        memcap_per_segment(LRU_CACHE_INITIAL_SIZE) { }
    HostCacheSegmented(uint8_t segment_count, size_t memcap_per_segment);

    void init();
    void term();
    void setup(uint8_t , size_t );

    const PegInfo* get_pegs() { return lru_cache_shared_peg_names; }
    size_t get_memcap_per_segment() { return memcap_per_segment.load(); }
    size_t get_valid_id(uint8_t idx);
    uint8_t get_segments() { return segment_count; }
    size_t get_max_size();
    size_t get_mem_chunk();
    PegCount* get_counts();

    void set_segments(uint8_t segments) { segment_count = segments; }
    void print_config();
    bool set_max_size(size_t max_size);
    bool reload_resize(size_t memcap_per_segment);
    bool reload_prune(size_t new_size, unsigned max_prune);
    void invalidate();
    void update_counts();
    void reset_counts();

    std::shared_ptr<Value> operator[](const Key& key);

    uint8_t get_segment_idx(Key val);
    std::shared_ptr<Value> find(const Key& key);
    std::shared_ptr<Value> find_else_create(const Key& key, bool* new_data);
    std::vector<std::pair<Key, std::shared_ptr<Value>>> get_all_data();
    bool find_else_insert(const Key& key, std::shared_ptr<Value>& value);
    bool remove(const Key& key);
    bool remove(const Key& key, typename LruCacheSharedMemcap
        <snort::SfIp, snort::HostTracker, HashIp, IpEqualTo, HTPurgatory>::Data& data);
    size_t mem_size();

    std::vector<HostCacheIp*> seg_list;
    HostCacheIp* default_cache = &default_host_cache; // Default cache used for host tracker

private:
    uint8_t segment_count;
    std::atomic<size_t> memcap_per_segment;
    struct LruCacheSharedStats counts;
    bool init_done = false;
    std::mutex stats_lock;
};


template<typename Key, typename Value>
HostCacheSegmented<Key, Value>::HostCacheSegmented(uint8_t segment_count, size_t memcap_per_segment) :
    segment_count(segment_count),
    memcap_per_segment(memcap_per_segment)
{
    assert(segment_count > 0);

    for (size_t i = 0; i < this->segment_count; ++i)
    {
        auto cache = new HostCacheIp(this->memcap_per_segment);
        seg_list.emplace_back((HostCacheIp*)cache);
    }
    init_done = true;
}

template<typename Key, typename Value>
void HostCacheSegmented<Key, Value>::init()
{
    if(init_done or seg_list.size() >= segment_count)
        return;

    assert(segment_count > 0);

    for (size_t i = 0; i < segment_count; ++i)
    {
        auto cache = new HostCacheIp(memcap_per_segment.load());
        seg_list.emplace_back((HostCacheIp*)cache);
    }
    init_done = true;
}

template<typename Key, typename Value>
void HostCacheSegmented<Key, Value>::term()
{
    for (auto cache : seg_list)
    {
        if (cache)
            delete cache;
    }
}

template<typename Key, typename Value>
void HostCacheSegmented<Key, Value>::setup(uint8_t segs, size_t memcap )
{
    assert(segment_count > 0);

    segment_count = segs;
    memcap_per_segment = memcap/segs;
    set_max_size(memcap);
}

template<typename Key, typename Value>
size_t HostCacheSegmented<Key, Value>::get_valid_id(uint8_t idx)
{
    if(idx < seg_list.size())
        return seg_list[idx]->get_valid_id();
    return 0;
}

template<typename Key, typename Value>
void HostCacheSegmented<Key, Value>::print_config()
{
    if ( snort::SnortConfig::log_verbose() )
    {
        snort::LogLabel("host_cache");
        snort::LogMessage("    memcap: %zu bytes\n", get_max_size());
    }
}

template<typename Key, typename Value>
std::shared_ptr<Value> HostCacheSegmented<Key, Value>::operator[](const Key& key)
{
    return find_else_create(key, nullptr);
}

/**
 * Sets the maximum size for the entire cache, which is distributed equally
 * among all the segments.
 */
template<typename Key, typename Value>
bool HostCacheSegmented<Key, Value>::set_max_size(size_t max_size)
{
    bool success = true;
    memcap_per_segment = max_size/segment_count;
    for (auto cache : seg_list)
    {
        if (!cache->set_max_size(memcap_per_segment))
            success = false;
    }
    return success;
}

/**
 * Resize the cache based on the provided memory capacity, distributing the
 * memory equally among all the segments. If any segment fails to resize,
 * the operation is considered unsuccessful.
 */
template<typename Key, typename Value>
bool HostCacheSegmented<Key, Value>::reload_resize(size_t memcap)
{
    bool success = true;
    memcap_per_segment = memcap/segment_count;
    for (auto cache : seg_list)
    {
        if (!cache->reload_resize(memcap_per_segment.load()))
            success = false;
    }
    return success;
}

// Computes the index of the segment where a given key-value pair belongs.
template<typename Key, typename Value>
uint8_t HostCacheSegmented<Key, Value>::get_segment_idx(Key val)
{
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&val);
    uint8_t result = 0;
    for (size_t i = 0; i < sizeof(Key); ++i)
        result ^= bytes[i];
    //Assumes segment_count is a power of 2 always
    //This is a fast way to do a modulo operation
    return result & (segment_count - 1);
}

//Retrieves all the data stored across all the segments of the cache.
template<typename Key, typename Value>
std::vector<std::pair<Key, std::shared_ptr<Value>>>  HostCacheSegmented<Key,Value>::get_all_data()
{
    std::vector<std::pair<Key, std::shared_ptr<Value>>> all_data;

    for (auto cache : seg_list)
    {
        auto cache_data = cache->get_all_data();
        all_data.insert(all_data.end(), cache_data.begin(), cache_data.end());
    }
    return all_data;
}

template<typename Key, typename Value>
std::shared_ptr<Value> HostCacheSegmented<Key, Value>::find(const Key& key)
{
    uint8_t idx = get_segment_idx(key);
    return seg_list[idx]->find(key);
}

/**
 * Updates the internal counts of the host cache. This method aggregates the
 * counts from all segments and updates the overall counts for the cache.
 */
template<typename Key, typename Value>
void HostCacheSegmented<Key, Value>::update_counts()
{
    std::lock_guard<std::mutex> guard(stats_lock);
    PegCount* pcs = (PegCount*)&counts;
    const PegInfo* pegs = get_pegs();

    for (int i = 0; pegs[i].type != CountType::END; i++)
        pcs[i] = 0;

    for (auto cache : seg_list) 
    {
        const PegCount* cache_counts = cache->get_counts();
        cache->lock();
        cache->stats.bytes_in_use = cache->current_size;
        cache->stats.items_in_use = cache->list.size();
        for (int i = 0; pegs[i].type != CountType::END; i++)
            pcs[i] += cache_counts[i];
        cache->unlock();
    }
    host_cache_counts = counts;
}

template<typename Key, typename Value>
void HostCacheSegmented<Key, Value>::reset_counts()
{
    std::lock_guard<std::mutex> guard(stats_lock);
    const PegInfo* pegs = get_pegs();

    for (auto cache : seg_list)
    {
        PegCount* cache_counts = reinterpret_cast<PegCount*> (&cache->stats);
        cache->lock();
        for (int i = 0; pegs[i].type != CountType::END; i++)
            cache_counts[i] = 0;
        cache->unlock();
    }
}


template<typename Key, typename Value>
std::shared_ptr<Value> HostCacheSegmented<Key, Value>:: find_else_create(const Key& key, bool* new_data)
{
    // Determine the segment index where the key-value pair resides or should reside
    uint8_t idx = get_segment_idx(key);
    bool new_data_local = false;

    // Retrieve or create the entry for the key in the determined segment
    auto ht = seg_list[idx]->find_else_create(key, &new_data_local);
    if(new_data_local)
    {
        // If a new entry was created, update its cache interface and visibility
        ht->update_cache_interface(idx);
        ht->init_visibility(seg_list[idx]->get_valid_id());
    }
    if(new_data)
        *new_data = new_data_local;
    return ht;
}

template<typename Key, typename Value>
bool HostCacheSegmented<Key, Value>::find_else_insert(const Key& key, std::shared_ptr<Value>& value)
{
    uint8_t idx = get_segment_idx(key);
    return seg_list[idx]->find_else_insert(key, value, false);
}

template<typename Key, typename Value>
PegCount* HostCacheSegmented<Key, Value>::get_counts()
{
    if( init_done )
        update_counts();

    return (PegCount*)&host_cache_counts;
}

template<typename Key, typename Value>
void HostCacheSegmented<Key, Value>::invalidate()
{
    for( auto cache: seg_list)
    {
        cache->invalidate();
    }
}

template<typename Key, typename Value>
bool HostCacheSegmented<Key, Value>::reload_prune(size_t new_size, unsigned max_prune)
{
    bool success = true;
    memcap_per_segment = new_size/segment_count;
    for (auto cache : seg_list)
    {
        if (!cache->reload_prune(memcap_per_segment, max_prune))
            success = false;
    }
    return success;
}

template<typename Key, typename Value>
size_t HostCacheSegmented<Key, Value>::mem_size()
{
    size_t mem_size = 0;
    for (auto cache : seg_list)
    {
        if(cache)
            mem_size += cache->mem_size();
    }
    return mem_size;
}

template<typename Key, typename Value>
size_t HostCacheSegmented<Key, Value>::get_max_size()
{
    size_t max_size = 0;
    for (auto cache : seg_list)
        max_size += cache->get_max_size();
    return max_size;
}

template<typename Key, typename Value>
size_t HostCacheSegmented<Key, Value>::get_mem_chunk()
{
    //Assumes all segments have the same mem_chunk
    return seg_list[0]->mem_chunk;
}

template<typename Key, typename Value>
bool HostCacheSegmented<Key, Value>::remove(const Key& key)
{
    uint8_t idx = get_segment_idx(key);
    return seg_list[idx]->remove(key);
}

template<typename Key, typename Value>
bool HostCacheSegmented<Key, Value>::remove(const Key& key, typename LruCacheSharedMemcap<snort::SfIp, snort::HostTracker, HashIp, IpEqualTo, HTPurgatory>::Data& data)
{
    uint8_t idx = get_segment_idx(key);
    return seg_list[idx]->remove(key, data);
}

/*
Warning!!!: update_allocator and update_set_allocator don't copy data to old container
but erase it for speed. Use with care!!!
*/
template <template <typename, typename...> class Container, typename T, typename Alloc>
void update_allocator(Container<T, Alloc>& cont, CacheInterface* new_lru)
{
    Alloc new_allocator;
    new_allocator.set_cache(new_lru);
    cont = std::move(Container<T, Alloc>(new_allocator));
}

template <template <typename, typename, typename...> class Container, typename T, typename Comp, typename Alloc>
void update_set_allocator(Container<T, Comp, Alloc>& cont, CacheInterface* new_lru)
{
    Alloc new_allocator;
    new_allocator.set_cache(new_lru);
    cont = std::move(Container<T, Comp, Alloc> (new_allocator));
}


typedef HostCacheSegmented<snort::SfIp, snort::HostTracker> HostCacheSegmentedIp;
extern SO_PUBLIC HostCacheSegmentedIp host_cache;

#endif // HOST_CACHE_SEGMENTED_H

