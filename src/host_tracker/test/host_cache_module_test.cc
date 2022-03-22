//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_config.h"
#include "managers/module_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "sfip/sf_ip.h"

using namespace snort;

// All tests here use the same module since host_cache is global. Creating a local module for each
// test will cause host_cache PegCount testing to be dependent on the order of running these tests.
static HostCacheModule module;
#define LOG_MAX 128
static char logged_message[LOG_MAX+1];

static ControlConn ctrlcon(1, true);
ControlConn::ControlConn(int, bool) {}
ControlConn::~ControlConn() {}
ControlConn* ControlConn::query_from_lua(const lua_State*) { return &ctrlcon; }
bool ControlConn::respond(const char*, ...) { return true; }

namespace snort
{
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
} // end of namespace snort

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

template <class T>
HostCacheAllocIp<T>::HostCacheAllocIp()
{
    lru = &host_cache;
}

TEST_GROUP(host_cache_module)
{
};

static void try_reload_prune(bool is_not_locked)
{
    if ( is_not_locked )
    {
        CHECK(host_cache.reload_prune(host_cache.mem_chunk * 1.5, 2) == true);
    }
    else
    {
        CHECK(host_cache.reload_prune(host_cache.mem_chunk * 1.5, 2) == false);
    }
}

// Test stats when HostCacheModule sets/changes host_cache size.
// This method is a friend of LruCacheSharedMemcap class.
TEST(host_cache_module, misc)
{
    const PegInfo* ht_pegs = module.get_pegs();
    const PegCount* ht_stats = module.get_counts();

    CHECK(!strcmp(ht_pegs[0].name, "adds"));
    CHECK(!strcmp(ht_pegs[1].name, "alloc_prunes"));
    CHECK(!strcmp(ht_pegs[2].name, "find_hits"));
    CHECK(!strcmp(ht_pegs[3].name, "find_misses"));
    CHECK(!strcmp(ht_pegs[4].name, "reload_prunes"));
    CHECK(!strcmp(ht_pegs[5].name, "removes"));
    CHECK(!strcmp(ht_pegs[6].name, "replaced"));
    CHECK(!ht_pegs[7].name);

    // add 3 entries
    SfIp ip1, ip2, ip3;
    ip1.set("1.1.1.1");
    ip2.set("2.2.2.2");
    ip3.set("3.3.3.3");
    host_cache.find_else_create(ip1, nullptr);
    host_cache.find_else_create(ip2, nullptr);
    host_cache.find_else_create(ip3, nullptr);
    CHECK(ht_stats[0] == 3);

    // no pruning needed for resizing higher than current size
    CHECK(host_cache.reload_resize(host_cache.mem_chunk * 10) == false);

    // pruning needed for resizing lower than current size
    CHECK(host_cache.reload_resize(host_cache.mem_chunk * 1.5) == true);

    // pruning in thread is not done when reload_mutex is already locked
    host_cache.reload_mutex.lock();
    std::thread test_negative(try_reload_prune, false);
    test_negative.join();
    host_cache.reload_mutex.unlock();

    // prune 2 entries in thread when reload_mutex is not locked
    std::thread test_positive(try_reload_prune, true);
    test_positive.join();

    // alloc_prune 1 entry
    host_cache.find_else_create(ip1, nullptr);

    // 1 hit, 1 remove
    host_cache.find_else_create(ip1, nullptr);
    host_cache.remove(ip1);

    CHECK(ht_stats[0] == 4); // 4 adds
    CHECK(ht_stats[1] == 1); // 1 alloc_prunes
    CHECK(ht_stats[2] == 1); // 1 hit
    CHECK(ht_stats[3] == 4); // 4 misses
    CHECK(ht_stats[4] == 2); // 2 reload_prunes
    CHECK(ht_stats[5] == 1); // 1 remove

    ht_stats = module.get_counts();
    CHECK(ht_stats[0] == 4);
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
    // FIXIT-L There is currently no external way to fully release the memory from the global host
    //   cache unordered_map in host_cache.cc
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
