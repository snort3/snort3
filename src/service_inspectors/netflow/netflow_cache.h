//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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

// netflow_cache.h author Masud Hasan <mashasan@cisco.com>

#ifndef NETFLOW_CACHE_H
#define NETFLOW_CACHE_H

#include <cassert>

#include "hash/lru_cache_local.h"
#include "host_tracker/cache_allocator.h"
#include "sfip/sf_ip.h"

#include "netflow_headers.h"
#include "netflow_module.h"

// Trivial derived allocator, pointing to their own cache. LruCacheAllocNetflow has a
// CacheInterface* pointing to an lru cache. We can create different cache types by
// instantiating the lru cache using different keys and derive here allocators with
// CacheInterface* pointing to the appropriate lru cache object.
template <class T>
class LruCacheAllocNetflow : public CacheAlloc<T>
{
public:
    // This needs to be in every derived class:
    template <class U>
    struct rebind
    {
        typedef LruCacheAllocNetflow<U> other;
    };

    using CacheAlloc<T>::lru;
    LruCacheAllocNetflow();
};

template<typename Key, typename Value, typename Hash>
class LruCacheLocalNetflow : public LruCacheLocal<Key, Value, Hash>, public CacheInterface
{
public:
    using LruLocal = LruCacheLocal<Key, Value, Hash>;
    using LruLocal::current_size;
    using LruLocal::max_size;
    using LruLocal::list;

    LruCacheLocalNetflow(const size_t sz, struct LruCacheLocalStats& st) : LruLocal(sz, st) {}

    template <class T>
    friend class LruCacheAllocNetflow;

private:
    // Only the allocator calls this
    void update(int size) override
    {
        if ( size < 0 )
            assert( current_size >= (size_t) -size);

        // Checking 1+ size prevents crash if max_size is too low to hold even a single entry
        if ( (current_size += size) > max_size and list.size() > 1 )
            LruLocal::prune();
    }
};

template <class T>
class LruCacheAllocTemplate : public CacheAlloc<T>
{
public:
    template <class U>
    struct rebind
    {
        typedef LruCacheAllocTemplate<U> other;
    };

    using CacheAlloc<T>::lru;
    LruCacheAllocTemplate();
};

template<typename Key, typename Value, typename Hash>
class LruCacheLocalTemplate : public LruCacheLocal<Key, Value, Hash>, public CacheInterface
{
public:
    using LruLocal = LruCacheLocal<Key, Value, Hash>;
    using LruLocal::current_size;
    using LruLocal::max_size;
    using LruLocal::stats;
    using LruLocal::list;

    LruCacheLocalTemplate(const size_t sz, struct LruCacheLocalStats& st) : LruLocal(sz, st)
    {}

    bool insert(const Key& key, std::vector<Netflow9TemplateField>& tf)
    {
        bool is_new = false;
        Value& entry = LruLocal::find_else_create(key, &is_new);

        if ( !is_new )
        {
            stats.cache_replaces++;
            entry.clear();
        }

        for ( auto& elem : tf )
            entry.emplace_back(elem.field_type, elem.field_length);

        return is_new;
    }

    template <class T>
    friend class LruCacheAllocTemplate;

private:
    void update(int size) override
    {
        if ( size < 0 )
            assert( current_size >= (size_t) -size);

        if ( (current_size += size) > max_size and list.size() > 1 )
            LruLocal::prune();
    }
};

// Used to track record for unique IP; we assume Netflow packets coming from
// a given Netflow device will go to the same thread
typedef LruCacheLocalNetflow<snort::SfIp, NetflowSessionRecord, NetflowHash> NetflowCache;

// Used to track Netflow version 9 Template fields
typedef std::pair<uint16_t, snort::SfIp> TemplateFieldKey;
typedef LruCacheAllocTemplate<Netflow9TemplateField> TemplateAllocator;
typedef std::vector<Netflow9TemplateField, TemplateAllocator> TemplateFieldValue;
typedef LruCacheLocalTemplate<TemplateFieldKey, TemplateFieldValue, TemplateIpHash> TemplateFieldCache;

#endif
