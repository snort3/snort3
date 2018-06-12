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

// host_tracker_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for HostTracker class

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker/host_tracker.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
// Fake snort_strdup() because sfutil dependencies suck
char* snort_strdup(const char* str)
{ return strdup(str); }
}

TEST_GROUP(host_tracker)
{
};

//  Test HostTracker ipaddr get/set functions.
TEST(host_tracker, ipaddr_test)
{
    HostTracker ht;
    SfIp zeroed_sfip;
    SfIp expected_ip_addr;
    SfIp actual_ip_addr;

    //  Test IP prior to set.
    memset(&zeroed_sfip, 0, sizeof(zeroed_sfip));
    actual_ip_addr = ht.get_ip_addr();
    CHECK(0 == memcmp(&zeroed_sfip, &actual_ip_addr, sizeof(zeroed_sfip)));

    expected_ip_addr.pton(AF_INET6, "beef:abcd:ef01:2300::");
    ht.set_ip_addr(expected_ip_addr);
    actual_ip_addr = ht.get_ip_addr();
    CHECK(0 == memcmp(&expected_ip_addr, &actual_ip_addr, sizeof(expected_ip_addr)));
}

//  Test HostTracker policy get/set functions.
TEST(host_tracker, policy_test)
{
    HostTracker ht;
    Policy expected_policy = 23;
    Policy actual_policy;

    actual_policy = ht.get_stream_policy();
    CHECK(0 == actual_policy);

    actual_policy = ht.get_frag_policy();
    CHECK(0 == actual_policy);

    ht.set_stream_policy(expected_policy);
    actual_policy = ht.get_stream_policy();
    CHECK(expected_policy == actual_policy);

    expected_policy = 77;
    ht.set_frag_policy(expected_policy);
    actual_policy = ht.get_frag_policy();
    CHECK(expected_policy == actual_policy);
}

//  Test HostTracker add and find service functions.
TEST(host_tracker, add_find_service_test)
{
    bool ret;
    HostTracker ht;
    HostApplicationEntry actual_entry;
    HostApplicationEntry app_entry1(6, 2112, 3);
    HostApplicationEntry app_entry2(17, 7777, 10);

    //  Try a find on an empty list.
    ret = ht.find_service(3,1000, actual_entry);
    CHECK(false == ret);

    //  Test add and find.
    ret = ht.add_service(app_entry1);
    CHECK(true == ret);

    ret = ht.find_service(6, 2112, actual_entry);
    CHECK(true == ret);
    CHECK(actual_entry.port == 2112);
    CHECK(actual_entry.ipproto == 6);
    CHECK(actual_entry.snort_protocol_id == 3);

    ht.add_service(app_entry2);
    ret = ht.find_service(6, 2112, actual_entry);
    CHECK(true == ret);
    CHECK(actual_entry.port == 2112);
    CHECK(actual_entry.ipproto == 6);
    CHECK(actual_entry.snort_protocol_id == 3);

    ret = ht.find_service(17, 7777, actual_entry);
    CHECK(true == ret);
    CHECK(actual_entry.port == 7777);
    CHECK(actual_entry.ipproto == 17);
    CHECK(actual_entry.snort_protocol_id == 10);

    //  Try adding an entry that exists already.
    ret = ht.add_service(app_entry1);
    CHECK(false == ret);

    // Try a find on a port that isn't in the list.
    ret = ht.find_service(6, 100, actual_entry);
    CHECK(false == ret);

    // Try a find on an ipproto that isn't in the list.
    ret = ht.find_service(17, 2112, actual_entry);
    CHECK(false == ret);

    //  Try to remove an entry that's not in the list.
    ret = ht.remove_service(6,100);
    CHECK(false == ret);

    ret = ht.remove_service(17,2112);
    CHECK(false == ret);

    //  Actually remove an entry.
    ret = ht.remove_service(6,2112);
    CHECK(true == ret);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

