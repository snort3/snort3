//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "host_tracker/host_cache_module.h"
#include "host_tracker/host_cache.h"
#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "sfip/sf_ip.h"

using namespace snort;

namespace snort
{
//  Fakes to avoid bringing in a ton of dependencies.
SnortProtocolId ProtocolReference::add(char const*) { return 0; }
SnortProtocolId ProtocolReference::find(char const*) { return 0; }
SnortConfig* SnortConfig::get_conf() { return nullptr; }
char* snort_strdup(const char* s)
{ return strdup(s); }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*)
{ }

void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*)
{ }

#define FRAG_POLICY 33
#define STREAM_POLICY 100

SfIp expected_addr;

TEST_GROUP(host_cache_module)
{ };

//  Test that HostCacheModule sets up host_cache size based on config.
TEST(host_cache_module, host_cache_module_test_values)
{
    Value size_val((double)2112);
    Parameter size_param = { "size", Parameter::PT_INT, nullptr, nullptr, "cache size" };
    HostCacheModule module;
    const PegInfo* ht_pegs = module.get_pegs();
    const PegCount* ht_stats = module.get_counts();

    CHECK(!strcmp(ht_pegs[0].name, "lru_cache_adds"));
    CHECK(!strcmp(ht_pegs[1].name, "lru_cache_replaces"));
    CHECK(!strcmp(ht_pegs[2].name, "lru_cache_prunes"));
    CHECK(!strcmp(ht_pegs[3].name, "lru_cache_find_hits"));
    CHECK(!strcmp(ht_pegs[4].name, "lru_cache_find_misses"));
    CHECK(!strcmp(ht_pegs[5].name, "lru_cache_removes"));
    CHECK(!strcmp(ht_pegs[6].name, "lru_cache_clears"));
    CHECK(!ht_pegs[7].name);

    CHECK(ht_stats[0] == 0);
    CHECK(ht_stats[1] == 0);
    CHECK(ht_stats[2] == 0);
    CHECK(ht_stats[3] == 0);
    CHECK(ht_stats[4] == 0);
    CHECK(ht_stats[5] == 0);
    CHECK(ht_stats[6] == 0);

    size_val.set(&size_param);

    // Set up the host_cache max size.
    module.begin("host_cache", 0, nullptr);
    module.set(nullptr, size_val, nullptr);
    module.end("host_cache", 0, nullptr);

    ht_stats = module.get_counts();
    CHECK(ht_stats[0] == 0);

    CHECK(2112 == host_cache.get_max_size());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

