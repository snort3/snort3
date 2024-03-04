//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// host_cache_module_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for the host module APIs

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdarg>
#include <thread>

#include "control/control.h"
#include "host_tracker/host_cache_module.h"
#include "host_tracker/host_cache.h"
#include "host_tracker/host_cache_segmented.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/module_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "sfip/sf_ip.h"

using namespace snort;

HostCacheIp default_host_cache(LRU_CACHE_INITIAL_SIZE);
HostCacheSegmentedIp host_cache(4,LRU_CACHE_INITIAL_SIZE);
THREAD_LOCAL struct LruCacheSharedStats host_cache_counts;

// All tests here use the same module since host_cache is global. Creating a local module for each
// test will cause host_cache PegCount testing to be dependent on the order of running these tests.
static HostCacheModule module;
#define LOG_MAX 128
static char logged_message[LOG_MAX+1];

static ControlConn ctrlcon(1, true);
ControlConn::ControlConn(int, bool) : shell(nullptr), fd(-1), touched(0)
{ }
ControlConn::~ControlConn() {}
void ControlConn::log_command(const std::string& , bool ) { }
ControlConn* ControlConn::query_from_lua(const lua_State*) { return &ctrlcon; }
bool ControlConn::respond(const char*, ...) { return true; }

namespace snort
{
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }

const SnortConfig* SnortConfig::get_conf()
{ return nullptr; }

char* snort_strdup(const char* s)
{ return strdup(s); }

Module* ModuleManager::get_module(const char*)
{ return nullptr; }

void LogMessage(const char* format,...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(logged_message, LOG_MAX, format, args);
    va_end(args);
    logged_message[LOG_MAX] = '\0';
}
time_t packet_time() { return 0; }
bool Snort::is_reloading() { return false; }
void SnortConfig::register_reload_handler(ReloadResourceTuner* rrt) { delete rrt; }
void FatalError(const char* fmt, ...) { (void)fmt; exit(1); }
unsigned get_instance_id()
{ return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }
} // end of namespace snort

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

template <class T>
HostCacheAllocIp<T>::HostCacheAllocIp()
{
    lru = host_cache.seg_list[0];
}

TEST_GROUP(host_cache_module)
{
};

static void try_reload_prune(bool is_not_locked)
{
    auto segs = host_cache.seg_list.size();
    auto prune_size = host_cache.seg_list[0]->mem_chunk * 1.5 * segs;
    if ( is_not_locked )
    {
        CHECK(host_cache.reload_prune(prune_size, 2) == true);
        for ( auto& seg : host_cache.seg_list )
        {
            CHECK(seg->get_max_size() == prune_size/segs);
        }
    }
    else
    {
        CHECK(host_cache.reload_prune(prune_size, 2) == false);
    }
}

TEST(host_cache_module, cache_segments)
{
    SfIp ip0, ip1, ip2, ip3;
    ip0.set("1.2.3.2");
    ip1.set("11.22.2.0");
    ip2.set("192.168.1.1");
    ip3.set("10.20.33.10");

    uint8_t segment0 = host_cache.get_segment_idx(ip0);
    uint8_t segment1 = host_cache.get_segment_idx(ip1);
    uint8_t segment2 = host_cache.get_segment_idx(ip2);
    uint8_t segment3 = host_cache.get_segment_idx(ip3);

    CHECK(segment0 == 0);
    CHECK(segment1 == 1);
    CHECK(segment2 == 2);
    CHECK(segment3 == 3);

    auto h0 = host_cache.find_else_create(ip0, nullptr);
    auto h1 = host_cache.find_else_create(ip1, nullptr);
    auto h2 = host_cache.find_else_create(ip2, nullptr);
    auto h3 = host_cache.find_else_create(ip3, nullptr);

    CHECK(segment0 == h0->get_cache_idx());
    CHECK(segment1 == h1->get_cache_idx());
    CHECK(segment2 == h2->get_cache_idx());
    CHECK(segment3 == h3->get_cache_idx());
}


// Test stats when HostCacheModule sets/changes host_cache size.
// This method is a friend of LruCacheSharedMemcap class.
TEST(host_cache_module, misc)
{
    // memory chunk, computed as in the base cache class
    static constexpr size_t mc = sizeof(HostCacheIp::Data) + sizeof(HostCacheIp::ValueType);

    const PegInfo* ht_pegs = module.get_pegs();
    const PegCount* ht_stats = module.get_counts();

    CHECK(!strcmp(ht_pegs[0].name, "adds"));
    CHECK(!strcmp(ht_pegs[1].name, "alloc_prunes"));
    CHECK(!strcmp(ht_pegs[2].name, "bytes_in_use"));
    CHECK(!strcmp(ht_pegs[3].name, "items_in_use"));
    CHECK(!strcmp(ht_pegs[4].name, "find_hits"));
    CHECK(!strcmp(ht_pegs[5].name, "find_misses"));
    CHECK(!strcmp(ht_pegs[6].name, "reload_prunes"));
    CHECK(!strcmp(ht_pegs[7].name, "removes"));
    CHECK(!strcmp(ht_pegs[8].name, "replaced"));
    CHECK(!ht_pegs[9].name);

    // call this to set up the counts vector, before inserting hosts into the
    // cache, because sum_stats resets the pegs.
    module.sum_stats(true);

    // add 3 entries to segment 3 
    SfIp ip1, ip2, ip3;
    ip1.set("1.1.1.1");
    ip2.set("2.2.2.2");
    ip3.set("3.3.3.3");
    
    host_cache.find_else_create(ip1, nullptr);
    host_cache.find_else_create(ip2, nullptr);
    host_cache.find_else_create(ip3, nullptr);
    module.sum_stats(true);      // does not call reset
    CHECK(ht_stats[0] == 3);
    CHECK(ht_stats[2] == 3*mc);  // bytes_in_use
    CHECK(ht_stats[3] == 3);     // items_in_use

    // no pruning needed for resizing higher than current size in segment 3
    CHECK(host_cache.seg_list[2]->reload_resize(host_cache.get_mem_chunk() * 10 ) == false);
    module.sum_stats(true);
    CHECK(ht_stats[2] == 3*mc);  // bytes_in_use unchanged
    CHECK(ht_stats[3] == 3);     // items_in_use unchanged

    // pruning needed for resizing lower than current size in segment 3
    CHECK(host_cache.seg_list[2]->reload_resize(host_cache.get_mem_chunk() * 1.5) == true);
    module.sum_stats(true);
    CHECK(ht_stats[2] == 3*mc);  // bytes_in_use still unchanged
    CHECK(ht_stats[3] == 3);     // items_in_use still unchanged

    // pruning in thread is not done when reload_mutex is already locked
    for(auto cache : host_cache.seg_list)
        cache->reload_mutex.lock();
        
    std::thread test_negative(try_reload_prune, false);
    test_negative.join();

    for(auto cache : host_cache.seg_list)
        cache->reload_mutex.unlock();

    module.sum_stats(true);
    CHECK(ht_stats[2] == 3*mc);   // no pruning yet
    CHECK(ht_stats[3] == 3);      // no pruning_yet

    // prune 2 entries in thread when reload_mutex is not locked
    std::thread test_positive(try_reload_prune, true);
    test_positive.join();

    module.sum_stats(true);
    CHECK(ht_stats[2] == mc);
    CHECK(ht_stats[3] == 1);     // one left

    // alloc_prune 1 entry
    host_cache.find_else_create(ip1, nullptr);

    // 1 hit, 1 remove
    host_cache.find_else_create(ip1, nullptr);
    host_cache.remove(ip1);

    module.sum_stats(true);
    CHECK(ht_stats[0] == 4); // 4 adds
    CHECK(ht_stats[1] == 1); // 1 alloc_prunes
    CHECK(ht_stats[2] == 0); // 0 bytes_in_use
    CHECK(ht_stats[3] == 0); // 0 items_in_use
    CHECK(ht_stats[4] == 1); // 1 hit
    CHECK(ht_stats[5] == 4); // 4 misses
    CHECK(ht_stats[6] == 2); // 2 reload_prunes
    CHECK(ht_stats[7] == 1); // 1 remove

    ht_stats = module.get_counts();
    CHECK(ht_stats[0] == 4);
}


// Test host_cache.get_segment_stats()
TEST(host_cache_module, get_segment_stats)
{
    host_cache.init();
    std::string str;
    str = module.get_host_cache_segment_stats(0);

    bool contain = str.find("Segment 0:") != std::string::npos;
    CHECK_TRUE(contain);

    str = module.get_host_cache_segment_stats(1);
    contain = str.find("Segment 1:") != std::string::npos;
    CHECK_TRUE(contain);

    str = module.get_host_cache_segment_stats(2);
    contain = str.find("Segment 2:") != std::string::npos;
    CHECK_TRUE(contain);

    str = module.get_host_cache_segment_stats(-1);
    contain = str.find("total cache segments: 4") != std::string::npos;
    CHECK_TRUE(contain);
    

}

TEST(host_cache_module, log_host_cache_messages)
{
    module.log_host_cache(nullptr, true);
    STRCMP_EQUAL(logged_message, "File name is needed!\n");

    module.log_host_cache("nowhere/host_cache.dump", true);
    STRCMP_EQUAL(logged_message, "Couldn't open nowhere/host_cache.dump to write!\n");

    module.log_host_cache("host_cache.dump", true);
    STRCMP_EQUAL(logged_message, "Dumped host cache to host_cache.dump\n");

    module.log_host_cache("host_cache.dump", true);
    STRCMP_EQUAL(logged_message, "File host_cache.dump already exists!\n");
    remove("host_cache.dump");
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    int ret = CommandLineTestRunner::RunAllTests(argc, argv);
    host_cache.term();
    return ret;
}
