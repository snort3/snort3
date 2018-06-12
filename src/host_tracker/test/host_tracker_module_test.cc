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

// host_tracker_module_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for the host module APIs

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker/host_cache.h"
#include "host_tracker/host_tracker_module.h"
#include "target_based/snort_protocols.h"
#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
SnortConfig* SnortConfig::get_conf() { return nullptr; }
SnortProtocolId ProtocolReference::find(char const*) { return 0; }
SnortProtocolId ProtocolReference::add(const char* protocol)
{
    if (!strcmp("servicename", protocol))
        return 3;
    if (!strcmp("tcp", protocol))
        return 2;
    return 1;
}

char* snort_strdup(const char* s)
{ return strdup(s); }
}

//  Fake show_stats to avoid bringing in a ton of dependencies.
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

#define FRAG_POLICY 33
#define STREAM_POLICY 100

SfIp expected_addr;

TEST_GROUP(host_tracker_module)
{
    void setup() override
    {
        Value ip_val("10.23.45.56");
        Value frag_val((double)FRAG_POLICY);
        Value tcp_val((double)STREAM_POLICY);
        Value name_val("servicename");
        Value proto_val("udp");
        Value port_val((double)2112);
        Parameter ip_param = { "ip", Parameter::PT_ADDR, nullptr, "0.0.0.0/32", "addr/cidr"};
        Parameter frag_param = { "frag_policy", Parameter::Parameter::PT_ENUM, "linux | bsd", nullptr, "frag policy"};
        Parameter tcp_param = { "tcp_policy", Parameter::PT_ENUM, "linux | bsd", nullptr, "tcp policy"};
        Parameter name_param = {"name", Parameter::PT_STRING, nullptr, nullptr, "name"};
        Parameter proto_param = {"proto", Parameter::PT_ENUM, "tcp | udp", "tcp", "ip proto"};
        Parameter port_param = {"port", Parameter::PT_PORT, nullptr, nullptr, "port num"};
        HostTrackerModule module;
        const PegInfo* ht_pegs = module.get_pegs();
        const PegCount* ht_stats = module.get_counts();

        CHECK(!strcmp(ht_pegs[0].name, "service_adds"));
        CHECK(!strcmp(ht_pegs[1].name, "service_finds"));
        CHECK(!strcmp(ht_pegs[2].name, "service_removes"));
        CHECK(!ht_pegs[3].name);

        CHECK(ht_stats[0] == 0);
        CHECK(ht_stats[1] == 0);
        CHECK(ht_stats[2] == 0);

        ip_val.set(&ip_param);
        frag_val.set(&frag_param);
        tcp_val.set(&tcp_param);
        name_val.set(&name_param);
        proto_val.set(&proto_param);
        port_val.set(&port_param);

        // Change IP from string to integer representation.
        ip_param.validate(ip_val);

        // Set up the module values and add a service.
        module.begin("host_tracker", 1, nullptr);
        module.set(nullptr, ip_val, nullptr);
        module.set(nullptr, frag_val, nullptr);
        module.set(nullptr, tcp_val, nullptr);

        // FIXIT-M see FIXIT-M below
        //module.set(nullptr, name_val, nullptr);
        //module.set(nullptr, proto_val, nullptr);

        module.set(nullptr, port_val, nullptr);
        module.end("host_tracker.services", 1, nullptr);
        module.end("host_tracker", 1, nullptr);

        ip_val.get_addr(expected_addr);
    }

    void teardown() override
    {
        memset(&host_tracker_stats, 0, sizeof(host_tracker_stats));
        host_cache.clear();    //  Free HostTracker objects
    }
};

TEST(host_tracker_module, host_tracker_module_test_basic)
{
    CHECK(true);
}

#if 0
// FIXIT-M the below are more functional in scope because they require host_cache
// services.  need to stub this out better to focus on the module only.
//  Test that HostTrackerModule variables are set correctly.
TEST(host_tracker_module, host_tracker_module_test_values)
{
    SfIp cached_addr;

    HostIpKey host_ip_key((const uint8_t*) expected_addr.get_ip6_ptr());
    std::shared_ptr<HostTracker> ht;

    bool ret = host_cache.find(host_ip_key, ht);
    CHECK(ret == true);

    cached_addr = ht->get_ip_addr();
    CHECK(cached_addr.fast_equals_raw(expected_addr) == true);

    Policy policy = ht->get_stream_policy();
    CHECK(policy == STREAM_POLICY + 1);

    policy = ht->get_frag_policy();
    CHECK(policy == FRAG_POLICY + 1);
}


//  Test that HostTrackerModule statistics are correct.
TEST(host_tracker_module, host_tracker_module_test_stats)
{
    HostIpKey host_ip_key((const uint8_t*) expected_addr.get_ip6_ptr());
    std::shared_ptr<HostTracker> ht;

    bool ret = host_cache.find(host_ip_key, ht);
    CHECK(ret == true);

    HostApplicationEntry app;
    ret = ht->find_service(1, 2112, app);
    CHECK(ret == true);
    CHECK(app.protocol == 3);
    CHECK(app.ipproto == 1);
    CHECK(app.port == 2112);

    ret = ht->remove_service(1, 2112);
    CHECK(ret == true);

    //  Verify counts are correct.  The add was done during setup.
    CHECK(host_tracker_stats.service_adds == 1);
    CHECK(host_tracker_stats.service_finds == 1);
    CHECK(host_tracker_stats.service_removes == 1);
}
#endif

int main(int argc, char** argv)
{
    //  This is necessary to prevent the cpputest memory leak
    //  detection from thinking there's a memory leak in the map
    //  object contained within the global host_cache.  The map
    //  must have some data allocated when it is first created
    //  that doesn't go away until the global map object is
    //  deallocated. This pre-allocates the map so that initial
    //  allocation is done prior to starting the tests.
    HostTracker* ht = new HostTracker;
    host_cache_add_host_tracker(ht);
    host_cache.clear();

    return CommandLineTestRunner::RunAllTests(argc, argv);
}

