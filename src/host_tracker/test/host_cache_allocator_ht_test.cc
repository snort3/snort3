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

// host_cache_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for the host cache APIs

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker/cache_allocator.cc"
#include "host_tracker/host_cache.h"
#include "network_inspectors/rna/rna_flow.h"

#include <cstring>
#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace std;

namespace snort
{
// Fake snort_strdup() because sfutil dependencies suck
char* snort_strdup(const char* str)
{ return strdup(str); }
time_t packet_time() { return 0; }
void FatalError(const char* fmt, ...) { (void)fmt; exit(1);}
}
HostCacheIp default_host_cache(LRU_CACHE_INITIAL_SIZE);
HostCacheSegmentedIp host_cache(1,100);


template <class T>
class Allocator : public CacheAlloc<T>
{
public:
    template <class U>
    struct rebind
    {
        typedef Allocator<U> other;
    };

    using CacheAlloc<T>::lru;
    using Base = CacheAlloc<T>;

    void set_cache(CacheInterface* hci) { Base::set_lru(hci); }
    CacheInterface* get_cache_ptr() { return Base::get_lru(); }

    template <class U>
    Allocator(const Allocator<U>& other) 
    {
        lru = other.lru;
    }
    template <class U>
    Allocator(const Allocator<U>&& other) 
    {
        lru = other.lru;
    }
    Allocator();
};


class Item
{
public:
    typedef int ValueType;
    vector<ValueType, Allocator<ValueType>> data;
};

typedef LruCacheSharedMemcap<string, Item, hash<string>> CacheType;
CacheType cache1(100);
CacheType cache2(100);

template <class T>
Allocator<T>::Allocator()
{
    lru = &cache1;
}


TEST_GROUP(host_cache_allocator_ht)
{

};

TEST(host_cache_allocator_ht, allocate_update)
{   
    //declare a list with allocator cache
    std::list<string, Allocator<string>> test_list;
    CHECK(test_list.get_allocator().get_lru() == &cache1);
    //update cache interface of test_list to cache_2
    update_allocator(test_list, &cache2);
    CHECK(test_list.get_allocator().get_lru() == &cache2);
}

// Test allocation / deallocation, pruning and remove.
TEST(host_cache_allocator_ht, allocate)
{
    uint8_t hk[16];
    SfIp ip;
    const size_t n = 5, m = 3;
    const size_t hc_item_sz = sizeof(HostCacheIp::Data) + sizeof(HostTracker);
    const size_t ht_item_sz = sizeof(HostApplication);

    // room for n host trackers in the cache and 2^floor(log2(3))+2^ceil(log2(3))-1 host
    // applications in ht
    const size_t max_size = n * hc_item_sz + m * ht_item_sz;
    host_cache.set_max_size(max_size);

    // insert n empty host trackers:
    for (size_t i = 0; i < n; i++)
    {
        memset(hk, 0, 16);
        hk[i] = (uint8_t) i;
        ip.set(hk);

        // auto ht_ptr = host_cache.find(ip);
        auto ht_ptr = host_cache[ip];
        CHECK(ht_ptr != nullptr);
    }

    // insert m host tracker items (host applications) into the most recent
    // host tracker
    size_t i = n - 1;
    memset(hk, 0, 16);
    hk[i] = (uint8_t) i;
    ip.set(hk);

    {
        // Do insertion inside a scope, so that the host tracker pointer goes
        // out of scope. That's because when we remove (below this scope),
        // we don't want to have any unnecessary reference counts, as those
        // will delay calling the host tracker destructor.
        auto ht_ptr = host_cache[ip];
        CHECK(ht_ptr != nullptr);

        for (size_t port = 0; port + 1 < m; port++)
            CHECK(true == ht_ptr->add_service(port, IpProtocol::TCP, 676, true));

        // Insert a new host tracker item. The sequence of operations is this:
        // - host tracker vector is holding 2 * <ht_item_sz> bytes and wants to double in size.
        // - the allocator honors the vector's request, allocating 4 * <ht_item_sz> bytes and
        //   informs the host_cache about the new size, which exceeds max_size
        // - host_cache prunes, removing the least recent host tracker.
        //   Since this ht is empty, precisely <hc_item_sz> bytes are freed.
        // - the host tracker vector destructor frees up an additional 2 * <ht_item_sz> bytes
        //   that it reallocated.
        // Hence, after the next insert, the math is this:
        size_t sz = host_cache.mem_size() + 4 * ht_item_sz - hc_item_sz - 2 * ht_item_sz;

        CHECK(true == ht_ptr->add_service(m, IpProtocol::TCP, 676, true));
        CHECK(sz == host_cache.mem_size());
    }

    // Try a remove too, to catch any potential deadlocks.
    //
    // The host cache remove() function locks the cache, and then destroys
    // a host tracker. The host tracker destructor locks the cache again
    // via the allocator, thus leading to a race condition. This condition
    // is addressed in the remove() function by setting a temporary shared
    // pointer to the host tracker being deleted. This will postpone the
    // call to the host tracker destructor until after remove() releases
    // the lock.
    //
    // As a consequence, to test for this potential race condition, there
    // must be no exogenous pointers to the host tracker being removed, as
    // any such reference will inherently  break the deadlock. We want to see
    // that this mechanism is built-in into the remove function.

    bool res = host_cache.remove(ip);
    CHECK(res == true);

    // And, finally, a remove with a reference too:
    i--;
    memset(hk, 0, 16);
    hk[i] = (uint8_t) i;
    ip.set(hk);

    HostCacheIp::Data ht_ptr;
    res = host_cache.remove(ip, ht_ptr);
    CHECK(res == true);
    CHECK(ht_ptr != nullptr);
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    int ret = CommandLineTestRunner::RunAllTests(argc, argv);
    host_cache.term();
    return ret;
}
