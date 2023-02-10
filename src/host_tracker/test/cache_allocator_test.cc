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

// cache_allocator_test.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker/host_cache.h"
#include "host_tracker/cache_allocator.cc"
#include "network_inspectors/rna/rna_flow.h"

#include <string>

#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

HostCacheIp host_cache(100);

using namespace std;
using namespace snort;

// Derive an allocator from CacheAlloc:
template <class T>
class Allocator : public CacheAlloc<T>
{
public:

    // This needs to be in every derived class:
    template <class U>
    struct rebind
    {
        typedef Allocator<U> other;
    };

    using CacheAlloc<T>::lru;

    Allocator();
};


// Define an lru item:
class Item
{
public:
    typedef int ValueType;
    vector<ValueType, Allocator<ValueType>> data;
};

// Instantiate a cache, as soon as we know the Item type:
typedef LruCacheSharedMemcap<string, Item, hash<string>> CacheType;
CacheType cache(100);

// Implement the allocator constructor AFTER we have a cache object
// to point to and the implementation of our base CacheAlloc:
template <class T>
Allocator<T>::Allocator()
{
    lru = &cache;
}

namespace snort
{
time_t packet_time() { return 0; }
}

TEST_GROUP(cache_allocator)
{
};

// Test allocation / deallocation and pruning.
TEST(cache_allocator, allocate)
{
    const size_t n = 5, m = 3;   // do not change, these need to be just right
    const size_t item_sz = sizeof(CacheType::Data) + sizeof(CacheType::ValueType);
    const size_t item_data_sz = sizeof(Item::ValueType);

    // room for n items in the cache and m data in the Item.
    const size_t max_size = n * item_sz + m * item_data_sz;

    cache.set_max_size(max_size);

    // insert n empty host trackers:
    for (size_t i=0; i<n; i++)
    {
        string key = to_string(i);
        auto item_ptr = cache[key];
        CHECK( item_ptr != nullptr );
    }

    // grow the oldest item in the cache enough to trigger pruning:
    string key = to_string(0);
    auto item_ptr = cache[key];
    CHECK( item_ptr != nullptr );

    for (size_t i = 0; i<m; i++)
        item_ptr->data.emplace_back(i);

    // the oldest (0) is no longer the oldest after the look-up above,
    // so it should still be in the cache:
    CHECK( cache.find(key) != nullptr );

    // however, the second oldest should have become oldest and be pruned:
    CHECK( cache.find(to_string(1)) == nullptr );
}

int main(int argc, char** argv)
{
    // FIXIT-L There is currently no external way to fully release the memory from the global host
    //   cache unordered_map in host_cache.cc
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
