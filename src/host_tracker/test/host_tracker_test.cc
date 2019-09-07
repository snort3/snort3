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

// host_tracker_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for HostTracker class

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "host_tracker/host_cache.h"
#include "host_tracker/host_cache_allocator.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace std;

static time_t test_time = 0;
namespace snort
{
// Fake snort_strdup() because sfutil dependencies suck
char* snort_strdup(const char* str)
{ return strdup(str); }
time_t packet_time() { return test_time; }
}

// There always needs to be a HostCacheIp associated with HostTracker,
// because any allocation / deallocation into the HostTracker will take up
// memory managed by the cache.
HostCacheIp host_cache(1024);

TEST_GROUP(host_tracker)
{
};

//  Test HostTracker find appid and add service functions.
TEST(host_tracker, add_find_service_test)
{
    // Having standalone host tracker objects works, but it should be avoided
    // because they take up memory from the host cache. OK for testing.
    HostTracker ht;

    //  Try a find on an empty list.
    CHECK(APP_ID_NONE == ht.get_appid(80, IpProtocol::TCP));

    //  Test add and find.
    CHECK(true == ht.add_service(80, IpProtocol::TCP, 676, true));
    CHECK(true == ht.add_service(443, IpProtocol::TCP, 1122));
    CHECK(676 == ht.get_appid(80, IpProtocol::TCP));
    CHECK(1122 == ht.get_appid(443, IpProtocol::TCP));

    //  Try adding an entry that exists already and update appid
    CHECK(true == ht.add_service(443, IpProtocol::TCP, 847));
    CHECK(847 == ht.get_appid(443, IpProtocol::TCP));

    // Try a find appid on a port that isn't in the list.
    CHECK(APP_ID_NONE == ht.get_appid(8080, IpProtocol::UDP));
}

//  Test copying data and deleting copied list
TEST(host_tracker, copy_data_test)
{
    test_time = 1562198400;
    HostTracker ht;
    u_int8_t mac[6] = {254, 237, 222, 173, 190, 239};
    ht.add_mac(mac, 50, 1);

    uint8_t p_hops = 0;
    uint32_t p_last_seen = 0;
    list<HostMac>* p_macs = nullptr;
    ht.copy_data(p_hops, p_last_seen, p_macs);

    CHECK(p_hops == 255);
    CHECK(p_last_seen == 1562198400);
    CHECK(p_macs != nullptr);
    CHECK(p_macs->size() == 1);
    const auto& copied_data = p_macs->front();
    CHECK(copied_data.ttl == 50);
    CHECK(copied_data.primary == 1);
    CHECK(copied_data.last_seen == 1562198400);
    CHECK(memcmp(copied_data.mac, mac, MAC_SIZE) == 0);

    delete p_macs;
}

TEST(host_tracker, stringify)
{
    test_time = 1562198400; // this time will be updated and should not be seen in stringify
    HostTracker ht;

    u_int8_t mac1[6] = {254, 237, 222, 173, 190, 239};
    u_int8_t mac2[6] = {202, 254, 192, 255, 238, 0};
    test_time = 1562198404; // this time should be the time of the first mac address
    ht.update_last_seen();
    ht.add_mac(mac1, 9, 0);
    test_time = 1562198407; // this time should be the time of the second mac address
    ht.update_last_seen();
    ht.add_mac(mac2, 3, 1); // this primary mac should go to the front of the list

    ht.add_service(80, IpProtocol::TCP, 676, true);
    test_time = 1562198409; // this time should be the last seen time of the host
    ht.update_last_seen();
    ht.add_service(443, IpProtocol::TCP, 1122);

    string host_tracker_string;
    ht.stringify(host_tracker_string);

    STRCMP_EQUAL(host_tracker_string.c_str(),
        "\n    hops: 255, time: 2019-07-04 00:00:09"
        "\nmacs size: 2"
        "\n    mac: CA:FE:C0:FF:EE:00, ttl: 3, primary: 1, time: 2019-07-04 00:00:07"
        "\n    mac: FE:ED:DE:AD:BE:EF, ttl: 9, primary: 0, time: 2019-07-04 00:00:04"
        "\nservices size: 2"
        "\n    port: 80, proto: 6, appid: 676, inferred"
        "\n    port: 443, proto: 6, appid: 1122");
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
