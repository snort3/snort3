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
// lru_segmented_cache_shared.h author Raza Shafiq <rshafiq@cisco.com>

#ifndef LRU_SEGMENTED_CACHE_SHARED_H
#define LRU_SEGMENTED_CACHE_SHARED_H

#include <cassert>
#include <vector>

#include "lru_cache_shared.h"

#define DEFAULT_SEGMENT_COUNT 4

template<typename Key, typename Value, typename Hash = std::hash<Key>, typename Eq = std::equal_to<Key>>
class SegmentedLruCache 
{
public:

    using LruCacheType = LruCacheShared<Key, Value, Hash, Eq>;
    using Data = typename LruCacheType::Data;

    SegmentedLruCache(const size_t initial_size, std::size_t segment_count = DEFAULT_SEGMENT_COUNT)
        :segment_count(segment_count)
    {
        assert( segment_count > 0 && ( segment_count & (segment_count - 1)) == 0 );

        segments.resize(segment_count);
        for( auto& segment : segments )
            segment = std::make_unique<LruCacheType>(initial_size/segment_count);

        assert( segment_count == segments.size() );
    }

    virtual ~SegmentedLruCache() = default;

    Data find(const Key& key)
    {
        std::size_t segment_idx = get_segment_idx(key);
        return segments[segment_idx]->find(key);
    }

    Data operator[](const Key& key)
    {
        std::size_t segment_idx = get_segment_idx(key);
        return (*segments[segment_idx])[key];
    }

    bool remove(const Key& key)
    {
        std::size_t segment_idx = get_segment_idx(key);
        return segments[segment_idx]->remove(key);
    }
    
    bool remove(const Key& key, Data& data)
    {
        std::size_t idx = get_segment_idx(key); 
        return segments[idx]->remove(key, data);
    }

    Data find_else_create(const Key& key, bool* new_data)
    {
        std::size_t segment_idx = get_segment_idx(key);
        return segments[segment_idx]->find_else_create(key, new_data);
    }

    bool find_else_insert(const Key& key, std::shared_ptr<Value>& data, bool replace = false)
    {
        std::size_t segment_idx = get_segment_idx(key);
        return segments[segment_idx]->find_else_insert(key, data, replace);
    }

    std::shared_ptr<Value> find_else_insert(const Key& key, std::shared_ptr<Value>& data, LcsInsertStatus* status, bool replace = false)
    {
        std::size_t segment_idx = get_segment_idx(key);
        return segments[segment_idx]->find_else_insert(key, data, status, replace);
    }
    
    bool set_max_size(size_t max_size)
    {
        bool success = true;
        size_t memcap_per_segment = max_size / segment_count;
        for ( const auto& segment : segments )
        {
            if ( !segment->set_max_size(memcap_per_segment) )
                success = false;
        }
        return success;
    }

    std::vector<std::pair<Key, std::shared_ptr<Value>>> get_all_data()
    {
        std::vector<std::pair<Key, std::shared_ptr<Value>>> all_data;

        for ( const auto& cache : segments )
        {
            auto cache_data = cache->get_all_data();
            all_data.insert(all_data.end(), cache_data.begin(), cache_data.end());
        }
        return all_data;
    }

    size_t mem_size()
    {
        size_t mem_size = 0;
        for ( const auto& cache : segments )
        {
            mem_size += cache->mem_size();
        }
        return mem_size;
    }

    const PegInfo* get_pegs() 
    { 
        return lru_cache_shared_peg_names; 
    }

    PegCount* get_counts() 
    {
        PegCount* pcs = (PegCount*)&counts;
        const PegInfo* pegs = get_pegs();

        for ( int i = 0; pegs[i].type != CountType::END; i++ )
        {
            PegCount c = 0;
            for ( const auto& cache : segments )
            {
                c += cache->get_counts()[i];
            }
            pcs[i] = c;
        }
        return (PegCount*)&counts;
    }

    size_t size() 
    {
        size_t total_size = 0;
        for ( const auto& cache : segments ) 
        {
            total_size += cache->size();
        }
        return total_size;
    }

    size_t get_max_size()
    {
        size_t max_size = 0;
        for ( const auto& cache : segments )
        {
            max_size += cache->get_max_size();
        }
        return max_size;
    }

    size_t get_segment_count() const
    {
        return segment_count;
    }

protected:
    std::size_t segment_count = DEFAULT_SEGMENT_COUNT;

private:
    std::vector<std::unique_ptr<LruCacheType>> segments;
    struct LruCacheSharedStats counts;

    //derived class can implement their own get_segment_idx if needed
    virtual std::size_t get_segment_idx(Key val)
    {
        if ( segment_count == 1 )
            return 0;
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&val);
        uint8_t result = 0;
        for ( size_t i = 0; i < sizeof(Key); ++i )
            result ^= bytes[i];
        // Assumes segment_count is a power of 2 always
        // This is a fast way to do a modulo operation
        return result & (segment_count - 1);
    }
};

#endif // LRU_SEGMENTED_CACHE_SHARED_H
