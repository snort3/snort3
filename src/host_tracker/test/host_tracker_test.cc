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

#include "host_tracker/host_tracker.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;
using namespace std;

namespace snort
{
// Fake snort_strdup() because sfutil dependencies suck
char* snort_strdup(const char* str)
{ return strdup(str); }
}

TEST_GROUP(host_tracker)
{
};

//  Test HostTracker find appid and add service functions.
TEST(host_tracker, add_find_service_test)
{
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

TEST(host_tracker, stringify)
{
    HostTracker ht;
    ht.add_service(80, IpProtocol::TCP, 676, true);
    ht.add_service(443, IpProtocol::TCP, 1122);
    string host_tracker_string;

    ht.stringify(host_tracker_string);
    STRCMP_EQUAL(host_tracker_string.c_str(),
        "\nservices size: 2"
        "\n    port: 80, proto: 6, appid: 676, inferred"
        "\n    port: 443, proto: 6, appid: 1122");
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

