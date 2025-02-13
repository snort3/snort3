//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "host_tracker/cache_allocator.cc"
#include "host_tracker/host_cache.h"
#include "network_inspectors/rna/rna_flow.h"

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
void FatalError(const char* fmt, ...) { (void)fmt; exit(1); }
}

// There always needs to be a HostCacheIp associated with HostTracker,
// because any allocation / deallocation into the HostTracker will take up
// memory managed by the cache.
HostCacheIp default_host_cache(LRU_CACHE_INITIAL_SIZE);
HostCacheSegmentedIp host_cache(4,1024);

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

//  Test HostTracker add and rediscover service payload
//  (reuse/rediscover a deleted payload)
TEST(host_tracker, add_rediscover_service_payload_test)
{
    HostTracker ht;
    HostApplication local_ha;

    ht.add_service(80, IpProtocol::TCP, 676, true);
    ht.add_service(443, IpProtocol::TCP, 1122);

    // Test adding payload
    // Add a payload for service http (appid 676), payload == appid 261
    // With 5 max payloads
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 261, 676, 5);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 100, 676, 5);

    auto services = ht.get_services();

    // Verify we added the services, payload visibility == true
    for (const auto& srv : services)
    {
        CHECK(true == srv.visibility);
        for (const auto& pld : srv.payloads)
            CHECK(true == pld.second);
    }

    // Delete the service
    ht.set_service_visibility(80, IpProtocol::TCP, false);

    // Verify that the service (and payloads) are deleted
    services = ht.get_services();
    for (const auto& srv : services)
    {
        if (srv.port == 80)
            CHECK(false == srv.visibility);
        for ( const auto& pld : srv.payloads )
            CHECK(false == pld.second);
    }

    // Test rediscovery
    // One payload is rediscovered as itself (existing payload with visibility = false)
    // The other payload uses an existing slot that was freed when payload 100 was deleted
    ht.add_service(80, IpProtocol::TCP, 676, true);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 261, 676, 5);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 101, 676, 5);

    services = ht.get_services();
    for (const auto& srv : services)
    {
        if (srv.port == 80)
            CHECK(true == srv.visibility);
        for ( const auto& pld : srv.payloads )
            CHECK(true == pld.second);
    }

    CHECK(2 == services.front().payloads.size());
}

//  Test HostTracker with max payloads and payload reuse
// (reuse a deleted payload for a new payload)
TEST(host_tracker, max_payloads_test)
{
    HostTracker ht;
    HostApplication local_ha;

    ht.add_service(80, IpProtocol::TCP, 676, true);

    // These payloads aren't valid payloads, but host tracker doesn't care
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 111, 676, 5);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 222, 676, 5);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 333, 676, 5);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 444, 676, 5);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 555, 676, 5);

    auto services = ht.get_services();

    // Verify we added the services, payload visibility == true
    CHECK(5 == services.front().payloads.size());

    for (const auto& pld : services.front().payloads)
        CHECK(true == pld.second);

    // Delete the service
    ht.set_service_visibility(80, IpProtocol::TCP, false);

    // Check all payloads are invisible after service visibility is false
    services = ht.get_services();
    for (const auto& pld : services.front().payloads)
        CHECK(false == pld.second);

    // Add a payload; we are already at max payloads, so re-use an existing slot
    ht.add_service(80, IpProtocol::TCP, 676, true);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 999, 676, 5);
    bool found_new = false;
    services = ht.get_services();
    for (const auto& pld : services.front().payloads)
    {
        if (pld.first == 999)
        {
            CHECK(true == pld.second);
            found_new = true;
        }
        else
        {
            CHECK(false == pld.second);
        }
    }

    // Check we still have only 5 payloads, and the new payload was added
    CHECK(5 == services.front().payloads.size() and found_new);
    CHECK(1 == services.front().num_visible_payloads);
}

//  Test HostTracker with simple client payload rediscovery
//  (reuse/rediscover a deleted payload)
TEST(host_tracker, client_payload_rediscovery_test)
{
    HostTracker ht;
    HostClient hc;
    bool new_client = false;

    // Create a new client, HTTP
    hc = ht.find_or_add_client(2, "one", 676, new_client);
    CHECK(true == new_client);

    // Add payloads 123 and 456
    ht.add_client_payload(hc, 123, 5);
    ht.add_client_payload(hc, 456, 5);
    auto clients = ht.get_clients();
    CHECK(2 == clients.front().payloads.size());

    // Delete client, ensure payloads are also deleted
    ht.set_client_visibility(hc, false);
    clients = ht.get_clients();
    for (const auto& pld : clients.front().payloads)
        CHECK(false == pld.second);

    // Rediscover client, make sure payloads are still deleted
    hc = ht.find_or_add_client(2, "one", 676, new_client);
    clients = ht.get_clients();
    for (const auto& pld : clients.front().payloads)
        CHECK(false == pld.second);

    // Re-add payloads, ensure they're actually visible now
    ht.add_client_payload(hc, 123, 5);
    ht.add_client_payload(hc, 456, 5);
    clients = ht.get_clients();
    for (const auto& pld : clients.front().payloads)
        CHECK(true == pld.second);

    CHECK(2 == clients.front().payloads.size());

    // Make sure we didn't just add an extra client and two new payloads, rather than reusing
    CHECK(1 == clients.size());
}

//  Test HostTracker with max payloads and payload reuse
// (reuse an old payload for a new payload)
TEST(host_tracker, client_payload_max_payloads_test)
{
    HostTracker ht;
    HostClient hc;
    bool new_client = false;

    // Create a new client, HTTP
    hc = ht.find_or_add_client(2, "one", 676, new_client);

    // Add five (max payloads) payloads
    ht.add_client_payload(hc, 111, 5);
    ht.add_client_payload(hc, 222, 5);
    ht.add_client_payload(hc, 333, 5);
    ht.add_client_payload(hc, 444, 5);
    ht.add_client_payload(hc, 555, 5);
    auto clients = ht.get_clients();
    CHECK_FALSE(ht.add_client_payload(hc, 666, 5));
    CHECK(5 == clients.front().payloads.size());

    // Delete client, ensure payloads are also deleted
    ht.set_client_visibility(hc, false);
    clients = ht.get_clients();
    for (const auto& pld : clients.front().payloads)
        CHECK(false == pld.second);

   // Rediscover client, make sure payloads are still deleted
    hc = ht.find_or_add_client(2, "one", 676, new_client);
    clients = ht.get_clients();
    for (const auto& pld : clients.front().payloads)
        CHECK(false == pld.second);

    CHECK(0 == clients.front().num_visible_payloads);

    //Re-add payloads, ensure they're actually visible now
    ht.add_client_payload(hc, 666, 5);
    ht.add_client_payload(hc, 777, 5);
    clients = ht.get_clients();
    for (const auto& pld : clients.front().payloads)
    {
        if (pld.first == 666 or pld.first == 777)
        {
            CHECK(true == pld.second);
        }
        else
        {
            CHECK(false == pld.second);
        }
    }

    CHECK(5 == clients.front().payloads.size());
    CHECK(2 == clients.front().num_visible_payloads);
    CHECK(1 == clients.size());
}

// Test user login information updates for service
TEST(host_tracker, update_service_user_test)
{
    HostTracker ht;

    CHECK(true == ht.add_service(110, IpProtocol::TCP, 788, false));

    // The first discoveries of both login success and login failure are updated
    CHECK(true == ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, true));
    CHECK(true == ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, false));

    // Subsequent discoveries for login success and login failure are not updated
    CHECK(false == ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, true));
    CHECK(false == ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, false));

    // Discoveries for a new user name are updated
    CHECK(true == ht.update_service_user(110, IpProtocol::TCP, "user2", 1, 1, false));
    CHECK(true == ht.update_service_user(110, IpProtocol::TCP, "user2", 1, 1, true));
}

//  Test copying data and deleting copied list
TEST(host_tracker, copy_data_test)
{
    test_time = 1562198400;
    HostTracker ht;
    uint8_t mac[6] = {254, 237, 222, 173, 190, 239};
    ht.add_mac(mac, 50, 1);

    uint8_t p_hops = 0;
    uint32_t p_last_seen = 0;
    list<HostMac>* p_macs = nullptr;
    ht.copy_data(p_hops, p_last_seen, p_macs);

    CHECK(255 == p_hops);
    CHECK(1562198400 == p_last_seen);
    CHECK(nullptr != p_macs);
    CHECK(1 == p_macs->size());
    const auto& copied_data = p_macs->front();
    CHECK(50 == copied_data.ttl);
    CHECK(1 == copied_data.primary);
    CHECK(1562198400 == copied_data.last_seen);
    CHECK(0 == memcmp(copied_data.mac, mac, MAC_SIZE));

    delete p_macs;
}

TEST(host_tracker, stringify)
{
    test_time = 1562198400; // this time will be updated and should not be seen in stringify
    HostTracker ht;

    uint8_t mac1[6] = {254, 237, 222, 173, 190, 239};
    uint8_t mac2[6] = {202, 254, 192, 255, 238, 0};
    test_time = 1562198404; // this time should be the time of the first mac address
    ht.update_last_seen();
    ht.add_mac(mac1, 9, 0);
    test_time = 1562198407; // this time should be the time of the second mac address
    ht.update_last_seen();
    ht.add_mac(mac2, 3, 1); // this primary mac should go to the back of the list

    ht.add_service(80, IpProtocol::TCP, 676, true);
    test_time = 1562198409; // this time should be the last seen time of the host
    ht.update_last_seen();
    ht.add_service(443, IpProtocol::TCP, 1122);

    string host_tracker_string;
    ht.stringify(host_tracker_string);

    STRCMP_EQUAL(host_tracker_string.c_str(),
        "\n    type: Host, ttl: 0, hops: 255, time: 2019-07-04 00:00:09"
        "\nmacs size: 2"
        "\n    mac: FE:ED:DE:AD:BE:EF, ttl: 9, primary: 0, time: 2019-07-04 00:00:04"
        "\n    mac: CA:FE:C0:FF:EE:00, ttl: 3, primary: 1, time: 2019-07-04 00:00:07"
        "\nservices size: 2"
        "\n    port: 80, proto: 6, appid: 676, inferred"
        "\n    port: 443, proto: 6, appid: 1122");
}

TEST(host_tracker, rediscover_host)
{
    test_time = 1562198400; // this time will be updated and should not be seen in stringify
    HostTracker ht;

    ht.add_service(80, IpProtocol::TCP, 676, true);
    ht.add_service(443, IpProtocol::TCP, 1122);
    CHECK(2 == ht.get_service_count());

    bool is_new;
    ht.find_or_add_client(1, "one", 100, is_new);
    ht.find_or_add_client(2, "two", 200, is_new);
    CHECK(2 == ht.get_client_count());

    ht.set_visibility(false);
    CHECK(0 == ht.get_service_count());

    // rediscover the host, no services and clients should be visible
    ht.set_visibility(true);
    CHECK(0 == ht.get_service_count());
    CHECK(0 == ht.get_client_count());

    // rediscover a service, that and only that should be visible
    ht.add_service(443, IpProtocol::TCP, 1122);
    CHECK(1 == ht.get_service_count());

    // change the appid of existing service
    HostApplication ha(443, IpProtocol::TCP, 1133, false);
    bool added;
    ht.add_service(ha, &added);
    CHECK(added);

    // rediscover service using a different add service function
    HostApplication ha2(80, IpProtocol::TCP, 676, false);
    bool ret = ht.add_service(ha2, &added);
    CHECK(ret);
    CHECK(added);

    // and a client
    ht.find_or_add_client(2, "one", 200, is_new);
    CHECK(1 == ht.get_client_count());

    string host_tracker_string;
    ht.stringify(host_tracker_string);

    string expected;
    expected += "\n    type: Host, ttl: 0, hops: 255, time: 2019-07-04 00:00:00";
    expected += "\nservices size: 2";
    expected += "\n    port: 80, proto: 6, appid: 676, inferred";
    expected += "\n    port: 443, proto: 6, appid: 1133";
    expected += "\nclients size: 1";
    expected += "\n    id: 2, service: 200, version: one";

    STRCMP_EQUAL(expected.c_str(), host_tracker_string.c_str());
}

int main(int argc, char** argv)
{
    int ret = CommandLineTestRunner::RunAllTests(argc, argv);
    host_cache.term();
    return ret;
}
