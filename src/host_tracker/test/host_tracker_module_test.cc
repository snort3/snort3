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

// host_tracker_module_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for the host module APIs

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "host_tracker/host_cache.h"
#include "host_tracker/host_tracker_module.h"
#include "main/snort_config.h"
#include "target_based/snort_protocols.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
char* snort_strdup(const char* s)
{ return strdup(s); }
time_t packet_time() { return 0; }
}

//  Fake show_stats to avoid bringing in a ton of dependencies.
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

SfIp expected_addr;

TEST_GROUP(host_tracker_module)
{
    void setup() override
    {
        Value ip_val("10.23.45.56");
        Value proto_val("udp");
        Value port_val((double)2112);
        Parameter ip_param = { "ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32", "addr/cidr"};
        Parameter proto_param = {"proto", Parameter::PT_ENUM, "tcp | udp", "tcp", "ip proto"};
        Parameter port_param = {"port", Parameter::PT_PORT, nullptr, nullptr, "port num"};
        HostTrackerModule module;
        const PegInfo* ht_pegs = module.get_pegs();
        const PegCount* ht_stats = module.get_counts();

        CHECK(!strcmp(ht_pegs[0].name, "service_adds"));
        CHECK(!strcmp(ht_pegs[1].name, "service_finds"));
        CHECK(!ht_pegs[2].name);

        CHECK(ht_stats[0] == 0);
        CHECK(ht_stats[1] == 0);

        ip_val.set(&ip_param);
        proto_val.set(&proto_param);
        port_val.set(&port_param);

        // Change IP from string to integer representation.
        ip_param.validate(ip_val);

        // Set up the module values and add a service.
        module.begin("host_tracker", 1, nullptr);
        module.set(nullptr, ip_val, nullptr);

        module.set(nullptr, port_val, nullptr);
        module.end("host_tracker.services", 1, nullptr);
        module.end("host_tracker", 1, nullptr);

        ip_val.get_addr(expected_addr);
    }

    void teardown() override
    {
        memset(&host_tracker_stats, 0, sizeof(host_tracker_stats));
    }
};

TEST(host_tracker_module, host_tracker_module_test_basic)
{
    CHECK(true);
}

int main(int argc, char** argv)
{
    // FIXIT-L There is currently no external way to fully release the memory from the global host
    //   cache unordered_map in host_cache.cc
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

