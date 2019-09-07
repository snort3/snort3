//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "host_tracker/host_cache_module.h"
#include "host_tracker/host_cache.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "sfip/sf_ip.h"

using namespace snort;
using namespace std;

// All tests here use the same module since host_cache is global. Creating a local module for each
// test will cause host_cache PegCount testing to be dependent on the order of running these tests.
static HostCacheModule module;
#define LOG_MAX 128
static char logged_message[LOG_MAX+1];

namespace snort
{
SnortConfig* SnortConfig::get_conf() { return nullptr; }
char* snort_strdup(const char* s) { return strdup(s); }
Module* ModuleManager::get_module(const char*) { return nullptr; }
void LogMessage(const char* format,...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(logged_message, LOG_MAX, format, args);
    va_end(args);
    logged_message[LOG_MAX] = '\0';
}
time_t packet_time() { return 0; }
}

extern "C"
{
const char* luaL_optlstring(lua_State*, int, const char*, size_t*) { return nullptr; }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

TEST_GROUP(host_cache_module)
{
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    }

    void teardown() override
    {
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

//  Test that HostCacheModule sets up host_cache size based on config.
TEST(host_cache_module, host_cache_module_test_values)
{
    Value size_val((double)2112);
    Parameter size_param = { "size", Parameter::PT_INT, nullptr, nullptr, "cache size" };
    const PegInfo* ht_pegs = module.get_pegs();
    const PegCount* ht_stats = module.get_counts();

    CHECK(!strcmp(ht_pegs[0].name, "lru_cache_adds"));
    CHECK(!strcmp(ht_pegs[1].name, "lru_cache_prunes"));
    CHECK(!strcmp(ht_pegs[2].name, "lru_cache_find_hits"));
    CHECK(!strcmp(ht_pegs[3].name, "lru_cache_find_misses"));
    CHECK(!strcmp(ht_pegs[4].name, "lru_cache_removes"));
    CHECK(!ht_pegs[5].name);

    CHECK(ht_stats[0] == 0);
    CHECK(ht_stats[1] == 0);
    CHECK(ht_stats[2] == 0);
    CHECK(ht_stats[3] == 0);
    CHECK(ht_stats[4] == 0);

    size_val.set(&size_param);

    // Set up the host_cache max size.
    module.begin("host_cache", 0, nullptr);
    module.set(nullptr, size_val, nullptr);
    module.end("host_cache", 0, nullptr);

    ht_stats = module.get_counts();
    CHECK(ht_stats[0] == 0);
}

TEST(host_cache_module, log_host_cache_messages)
{
    module.log_host_cache(nullptr, true);
    STRCMP_EQUAL(logged_message, "File name is needed!\n");

    module.log_host_cache("nowhere/host_cache.dump", true);
    STRCMP_EQUAL(logged_message, "Couldn't open nowhere/host_cache.dump to write!\n");

    module.log_host_cache("host_cache.dump", true);
    STRCMP_EQUAL(logged_message, "Dumped host cache of size = 0 to host_cache.dump\n");

    module.log_host_cache("host_cache.dump", true);
    STRCMP_EQUAL(logged_message, "File host_cache.dump already exists!\n");
    remove("host_cache.dump");
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
