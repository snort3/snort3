//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// appid_expected_flags_test.cc author maya dagon <mdagon@cisco.com>

#include "network_inspectors/appid/appid_detector.cc"
#include "network_inspectors/appid/service_plugins/service_detector.cc"

#include "appid_mock_definitions.h"
#include "appid_mock_inspector.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

class MockServiceDetector : public ServiceDetector
{
public:
    int validate(AppIdDiscoveryArgs&) override { return 0; }
};

AppIdSession* parent = nullptr;
AppIdSession* expected = nullptr;
MockServiceDetector test_detector;

uint64_t allFlags = APPID_SESSION_RESPONDER_MONITORED |  APPID_SESSION_INITIATOR_MONITORED |
    APPID_SESSION_SPECIAL_MONITORED | APPID_SESSION_RESPONDER_CHECKED |
    APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_DISCOVER_APP |
    APPID_SESSION_DISCOVER_USER;

static inline void cleanup()
{
    parent->clear_session_flags(allFlags);
    expected->clear_session_flags(allFlags);
}

TEST_GROUP(appid_expected_flags)
{
    void setup() override
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        parent = new AppIdSession(IpProtocol::TCP, nullptr, 1492, appid_inspector);
        expected = new AppIdSession(IpProtocol::TCP, nullptr, 1492, appid_inspector);
    }

    void teardown() override
    {
        delete parent;
        delete expected;
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(appid_expected_flags, test1)
{
    // Test 1 - expected flow same direction as parent, initiator monitored
    parent->set_session_flags(APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_INITIATOR_MONITORED);
    test_detector.initialize_expected_session(*parent, *expected, 0, APP_ID_FROM_INITIATOR);

    CHECK(expected->get_session_flags(allFlags) ==
        (APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_INITIATOR_MONITORED));

    cleanup();
}

TEST(appid_expected_flags, test2)
{
    // Test 2 - expected flow same direction as parent, responder monitored
    parent->set_session_flags(APPID_SESSION_RESPONDER_CHECKED | APPID_SESSION_RESPONDER_MONITORED);
    test_detector.initialize_expected_session(*parent, *expected, 0, APP_ID_FROM_INITIATOR);

    CHECK(expected->get_session_flags(allFlags) ==
        (APPID_SESSION_RESPONDER_CHECKED | APPID_SESSION_RESPONDER_MONITORED));

    cleanup();
}

TEST(appid_expected_flags, test3)
{
    // Test 3 - expected flow same direction as parent, all flags set
    parent->set_session_flags(allFlags);
    test_detector.initialize_expected_session(*parent, *expected, 0, APP_ID_FROM_INITIATOR);

    CHECK(expected->get_session_flags(allFlags) == allFlags);

    cleanup();
}

TEST(appid_expected_flags, test4)
{
    // Test 4 - expected flow opposite direction as parent, initiator monitored
    parent->set_session_flags(APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_INITIATOR_MONITORED);
    test_detector.initialize_expected_session(*parent, *expected, 0, APP_ID_FROM_RESPONDER);

    CHECK(expected->get_session_flags(allFlags) ==
        (APPID_SESSION_RESPONDER_CHECKED | APPID_SESSION_RESPONDER_MONITORED));

    cleanup();
}

TEST(appid_expected_flags, test5)
{
    // Test 5 - expected flow opposite direction as parent, responder monitored
    parent->set_session_flags(APPID_SESSION_RESPONDER_CHECKED | APPID_SESSION_RESPONDER_MONITORED);
    test_detector.initialize_expected_session(*parent, *expected, 0, APP_ID_FROM_RESPONDER);

    CHECK(expected->get_session_flags(allFlags) ==
        (APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_INITIATOR_MONITORED));

    cleanup();
}

TEST(appid_expected_flags, test6)
{
    // Test 6 - expected flow opposite direction as parent, all flags set
    parent->set_session_flags(allFlags);
    test_detector.initialize_expected_session(*parent, *expected, 0, APP_ID_FROM_RESPONDER);

    CHECK(expected->get_session_flags(allFlags) == allFlags);

    cleanup();
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

