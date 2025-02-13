//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// cache_allocator.h author Silviu Minut <sminut@cisco.com>

#ifndef CACHE_ALLOCATOR_H
#define CACHE_ALLOCATOR_H

#include <cassert>

#include "cache_interface.h"

template <class T>
class CacheAlloc : public std::allocator<T>
{
public:

    template <class U>
    struct rebind
    {
        typedef CacheAlloc<U> other;
    };

    T* allocate(std::size_t n);
    void deallocate(T* p, std::size_t n) noexcept;
    void set_lru(CacheInterface* c) { lru = c; }
    CacheInterface* get_lru() const { return lru; }

protected:

    CacheInterface* lru = nullptr;
};

template <class T>
T* CacheAlloc<T>::allocate(std::size_t n)
{
    size_t sz = n * sizeof(T);
    T* out = std::allocator<T>::allocate(n);
    lru->update(sz);
    return out;
}

template <class T>
void CacheAlloc<T>::deallocate(T* p, std::size_t n) noexcept
{
    size_t sz = n * sizeof(T);
    std::allocator<T>::deallocate(p, n);
    lru->update(-(int) sz);
}


// Trivial derived allocator, pointing to their own host cache.
// HostCacheAllocIp has a CacheInterface* pointing to an lru cache
// instantiated using snort::SfIp as the key. See host_cache.h.
// We can create different cache types by instantiating the lru cache using
// different keys and derive here allocators with CacheInterface*
// pointing to the appropriate lru cache object.
template <class T>
class HostCacheAllocIp : public CacheAlloc<T>
{
public:

    using Base = CacheAlloc<T>;
    // This needs to be in every derived class:
    template <class U>
    struct rebind
    {
        typedef HostCacheAllocIp<U> other;
    };

    using CacheAlloc<T>::lru;

    void set_cache(CacheInterface* hci) { Base::set_lru(hci); }
    CacheInterface* get_cache_ptr() { return Base::get_lru(); }

    template <class U>
    HostCacheAllocIp(const HostCacheAllocIp<U>& other)
    {
        this->lru = other.get_lru();
    }

    template <class U>
    HostCacheAllocIp(HostCacheAllocIp<U>&& other) noexcept
    {
        this->lru = other.get_lru();
    }

    HostCacheAllocIp();

};

#endif
