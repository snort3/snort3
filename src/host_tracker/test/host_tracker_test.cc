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
    for (auto& srv : services)
    {
        CHECK(srv.visibility);
        for (auto& pld : srv.payloads)
            CHECK(pld.second);
    }

    // Delete the service
    ht.set_service_visibility(80, IpProtocol::TCP, false);

    // Verify that the service (and payloads) are deleted
    services = ht.get_services();
    for (auto& srv : services)
    {
        if (srv.port == 80)
            CHECK(srv.visibility == false);
            for ( auto& pld : srv.payloads )
                CHECK(pld.second == false);
    }

    // Test rediscovery
    // One payload is rediscovered as itself (existing payload with visibility = false)
    // The other payload uses an existing slot that was freed when payload 100 was deleted
    ht.add_service(80, IpProtocol::TCP, 676, true);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 261, 676, 5);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 101, 676, 5);

    services = ht.get_services();
    for (auto& srv : services)
    {
        if (srv.port == 80)
            CHECK(srv.visibility == true);
            for ( auto& pld : srv.payloads )
                CHECK(pld.second);
    }

    CHECK(services.front().payloads.size() == 2);
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
    CHECK(services.front().payloads.size() == 5);

    for (auto& pld : services.front().payloads)
        CHECK(pld.second);

    // Delete the service
    ht.set_service_visibility(80, IpProtocol::TCP, false);

    // Check all payloads are invisible after service visibility is false
    services = ht.get_services();
    for (auto& pld : services.front().payloads)
        CHECK(pld.second == false);

    // Add a payload; we are already at max payloads, so re-use an existing slot
    ht.add_service(80, IpProtocol::TCP, 676, true);
    ht.add_payload(local_ha, 80, IpProtocol::TCP, 999, 676, 5);
    bool found_new = false;
    services = ht.get_services();
    for (auto& pld : services.front().payloads)
    {
        if (pld.first == 999)
        {
            CHECK(pld.second);
            found_new = true;
        }
        else
        {
            CHECK(pld.second == false);
        }
    }

    // Check we still have only 5 payloads, and the new payload was added
    CHECK(services.front().payloads.size() == 5 and found_new);
    CHECK(services.front().num_visible_payloads == 1);
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
    CHECK(new_client);

    // Add payloads 123 and 456
    ht.add_client_payload(hc, 123, 5);
    ht.add_client_payload(hc, 456, 5);
    auto clients = ht.get_clients();
    CHECK(clients.front().payloads.size() == 2);

    // Delete client, ensure payloads are also deleted
    ht.set_client_visibility(hc, false);
    clients = ht.get_clients();
    for (auto& pld : clients.front().payloads)
        CHECK(pld.second == false);

    // Rediscover client, make sure payloads are still deleted
    hc = ht.find_or_add_client(2, "one", 676, new_client);
    clients = ht.get_clients();
    for (auto& pld : clients.front().payloads)
        CHECK(pld.second == false);

    // Re-add payloads, ensure they're actually visible now
    ht.add_client_payload(hc, 123, 5);
    ht.add_client_payload(hc, 456, 5);
    clients = ht.get_clients();
    for (auto& pld : clients.front().payloads)
        CHECK(pld.second == true);

    CHECK(clients.front().payloads.size() == 2);

    // Make sure we didn't just add an extra client and two new payloads, rather than reusing
    CHECK(clients.size() == 1);
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
    CHECK(clients.front().payloads.size() == 5);

    // Delete client, ensure payloads are also deleted
    ht.set_client_visibility(hc, false);
    clients = ht.get_clients();
    for (auto& pld : clients.front().payloads)
        CHECK(pld.second == false);

   // Rediscover client, make sure payloads are still deleted
    hc = ht.find_or_add_client(2, "one", 676, new_client);
    clients = ht.get_clients();
    for (auto& pld : clients.front().payloads)
        CHECK(pld.second == false);

    CHECK(clients.front().num_visible_payloads == 0);

    //Re-add payloads, ensure they're actually visible now
    ht.add_client_payload(hc, 666, 5);
    ht.add_client_payload(hc, 777, 5);
    clients = ht.get_clients();
    for (auto& pld : clients.front().payloads)
    {
        if (pld.first == 666 or pld.first == 777)
        {
            CHECK(pld.second);
        }
        else
        {
            CHECK(pld.second == false);
        }
    }

    CHECK(clients.front().payloads.size() == 5);
    CHECK(clients.front().num_visible_payloads == 2);
    CHECK(clients.size() == 1);
}

// Test user login information updates for service
TEST(host_tracker, update_service_user_test)
{
    HostTracker ht;

    CHECK(ht.add_service(110, IpProtocol::TCP, 788, false) == true);

    // The first discoveries of both login success and login failure are updated
    CHECK(ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, true) == true);
    CHECK(ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, false) == true);

    // Subsequent discoveries for login success and login failure are not updated
    CHECK(ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, true) == false);
    CHECK(ht.update_service_user(110, IpProtocol::TCP, "user1", 1, 1, false) == false);

    // Discoveries for a new user name are updated
    CHECK(ht.update_service_user(110, IpProtocol::TCP, "user2", 1, 1, false) == true);
    CHECK(ht.update_service_user(110, IpProtocol::TCP, "user2", 1, 1, true) == true);
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
    CHECK(ht.get_service_count() == 2);

    bool is_new;
    ht.find_or_add_client(1, "one", 100, is_new);
    ht.find_or_add_client(2, "two", 200, is_new);
    CHECK(ht.get_client_count() == 2);

    ht.set_visibility(false);
    CHECK(ht.get_service_count() == 0);

    // rediscover the host, no services and clients should be visible
    ht.set_visibility(true);
    CHECK(ht.get_service_count() == 0);
    CHECK(ht.get_client_count() == 0);

    // rediscover a service, that and only that should be visible
    ht.add_service(443, IpProtocol::TCP, 1122);
    CHECK(ht.get_service_count() == 1);

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
    CHECK(ht.get_client_count() == 1);

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
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
