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

// host_cache_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for the host cache APIs

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker/host_cache.h"

#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
SnortConfig s_conf;
THREAD_LOCAL SnortConfig* snort_conf = &s_conf;
SnortConfig::SnortConfig(const SnortConfig* const) { }
SnortConfig::~SnortConfig() = default;
SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

SnortProtocolId ProtocolReference::find(char const*) { return 0; }
SnortProtocolId ProtocolReference::add(const char* protocol)
{
    if (!strcmp("servicename", protocol))
        return 3;
    if (!strcmp("tcp", protocol))
        return 2;
    return 1;
}

char* snort_strdup(const char* str)
{
    return strdup(str);
}
}

TEST_GROUP(host_cache)
{
};

//  Test HostIpKey
TEST(host_cache, host_ip_key_test)
{
    HostIpKey zeroed_hk;
    uint8_t expected_hk[16] =
    { 0xde,0xad,0xbe,0xef,0xab,0xcd,0xef,0x01,0x23,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };

    memset(&zeroed_hk.ip_addr, 0, sizeof(zeroed_hk.ip_addr));

    HostIpKey hkey1;
    CHECK(hkey1 == zeroed_hk);

    HostIpKey hkey2(expected_hk);
    CHECK(hkey2 == expected_hk);
}

//  Test HashHostIpKey
TEST(host_cache, hash_test)
{
    size_t expected_hash_val = 4521729;
    size_t actual_hash_val;
    uint8_t hk[16] =
    { 0x0a,0xff,0x12,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0x56,0x00,0x00,0x00,0x00,0x00 };

    HashHostIpKey hash_hk;

    actual_hash_val = hash_hk(hk);
    CHECK(actual_hash_val == expected_hash_val);
}

//  Test host_cache_add_host_tracker
TEST(host_cache, host_cache_add_host_tracker_test)
{
    HostTracker* expected_ht = new HostTracker;
    std::shared_ptr<HostTracker> actual_ht;
    uint8_t hk[16] =
    { 0xde,0xad,0xbe,0xef,0xab,0xcd,0xef,0x01,0x23,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };
    SfIp ip_addr;
    SfIp actual_ip_addr;
    HostIpKey hkey(hk);
    Port port = 443;
    Protocol proto = 6;
    HostApplicationEntry app_entry(proto, port, 2);
    HostApplicationEntry actual_app_entry;
    bool ret;

    ip_addr.pton(AF_INET6, "beef:dead:beef:abcd:ef01:2334:5678:90ab");

    expected_ht->set_ip_addr(ip_addr);
    expected_ht->add_service(app_entry);

    host_cache_add_host_tracker(expected_ht);

    ret = host_cache.find((const uint8_t*) ip_addr.get_ip6_ptr(), actual_ht);
    CHECK(true == ret);

    actual_ip_addr = actual_ht->get_ip_addr();
    CHECK(!memcmp(&ip_addr, &actual_ip_addr, sizeof(ip_addr)));

    ret = actual_ht->find_service(proto, port, actual_app_entry);
    CHECK(true == ret);
    CHECK(actual_app_entry == app_entry);

    host_cache.clear();     //  Free HostTracker objects
}

//  Test host_cache_add_service
TEST(host_cache, host_cache_add_service_test)
{
    HostTracker* expected_ht = new HostTracker;
    std::shared_ptr<HostTracker> actual_ht;
    uint8_t hk[16] =
    { 0xde,0xad,0xbe,0xef,0xab,0xcd,0xef,0x01,0x23,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };
    SfIp ip_addr1;
    SfIp ip_addr2;
    HostIpKey hkey(hk);
    Port port1 = 443;
    Port port2 = 22;
    Protocol proto1 = 17;
    Protocol proto2 = 6;
    HostApplicationEntry app_entry1(proto1, port1, 1);
    HostApplicationEntry app_entry2(proto2, port2, 2);
    HostApplicationEntry actual_app_entry;
    bool ret;

    ip_addr1.pton(AF_INET6, "beef:dead:beef:abcd:ef01:2334:5678:90ab");
    ip_addr2.pton(AF_INET6, "beef:dead:beef:abcd:ef01:2334:5678:90ab");

    //  Initialize cache with a HostTracker.
    host_cache_add_host_tracker(expected_ht);

    //  Add a service to a HostTracker that already exists.
    ret = host_cache_add_service(ip_addr1, proto1, port1, "udp");
    CHECK(true == ret);

    ret = host_cache.find((const uint8_t*) ip_addr1.get_ip6_ptr(), actual_ht);
    CHECK(true == ret);

    ret = actual_ht->find_service(proto1, port1, actual_app_entry);
    CHECK(true == ret);
    CHECK(actual_app_entry == app_entry1);

    //  Try adding service again (should fail since service exists).
    ret = host_cache_add_service(ip_addr1, proto1, port1, "udp");
    CHECK(false == ret);

    //  Add a service with a new IP.
    ret = host_cache_add_service(ip_addr2, proto2, port2, "tcp");
    CHECK(true == ret);

    ret = host_cache.find((const uint8_t*) ip_addr1.get_ip6_ptr(), actual_ht);
    CHECK(true == ret);

    ret = actual_ht->find_service(proto2, port2, actual_app_entry);
    CHECK(true == ret);
    CHECK(actual_app_entry == app_entry2);

    host_cache.clear();     //  Free HostTracker objects
}

int main(int argc, char** argv)
{
    SfIp ip_addr1;
    Protocol proto1 = 17;
    Port port1 = 443;

    ip_addr1.pton(AF_INET6, "beef:dead:beef:abcd:ef01:2334:5678:90ab");

    //  This is necessary to prevent the cpputest memory leak
    //  detection from thinking there's a memory leak in the map
    //  object contained within the global host_cache.  The map
    //  must have some data allocated when it is first created
    //  that doesn't go away until the global map object is
    //  deallocated. This pre-allocates the map so that initial
    //  allocation is done prior to starting the tests.  The same
    //  is true for the list used when adding a service.
    HostTracker* ht = new HostTracker;
    host_cache_add_host_tracker(ht);
    host_cache_add_service(ip_addr1, proto1, port1, "udp");

    host_cache.clear();

    //  Use this if you want to turn off memory checks entirely:
    // MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();

    return CommandLineTestRunner::RunAllTests(argc, argv);
}

