//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_detector_test.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "network_inspectors/appid/appid_detector.cc"

#include <string>

#include "protocols/protocol_ids.h"

#include "appid_mock_http_session.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

char* snort_strdup(const char* str)
{
    assert(str);
    size_t n = strlen(str) + 1;
    char* p = (char*)snort_alloc(n);
    memcpy(p, str, n);
    return p;
}

void ErrorMessage(const char*,...) { }
void WarningMessage(const char*,...) { }
void LogMessage(const char*,...) { }
void ParseWarning(WarningGroup, const char*, ...) { }

Flow* flow = nullptr;
AppIdSession* mock_session = nullptr;

class TestDetector : public AppIdDetector
{
public:
    TestDetector() { }
    ~TestDetector() { }

    void do_custom_init() override { }
    int validate(AppIdDiscoveryArgs&) override { return 0; }
    void register_appid(AppId, unsigned) override { }
};

TEST_GROUP(appid_detector_tests)
{
    void setup()
    {
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        flow = new Flow;
        mock_session = new AppIdSession(IpProtocol::TCP, nullptr, 1492);
        mock_session->hsession = init_http_session(mock_session);
        flow->set_flow_data(mock_session);
    }

    void teardown()
    {
        delete mock_session;
        delete flow;
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(appid_detector_tests, add_info)
{
    const char* info_url = "https://tools.ietf.org/html/rfc793";
    AppIdDetector* ad = new TestDetector;
    ad->add_info(mock_session, info_url);
    STRCMP_EQUAL(mock_session->hsession->url, URL);
    snort_free(mock_session->hsession->url);
    mock_session->hsession->url = nullptr;
    ad->add_info(mock_session, info_url);
    STRCMP_EQUAL(mock_session->hsession->url, info_url);
    delete ad;
}

TEST(appid_detector_tests, add_user)
{
    const char* username = "snorty";
    AppIdDetector* ad = new TestDetector;
    ad->add_user(mock_session, username, APPID_UT_ID, true);
    STRCMP_EQUAL(mock_session->username, username);
    CHECK_TRUE((mock_session->username_service == APPID_UT_ID));
    CHECK_TRUE((mock_session->get_session_flags(APPID_SESSION_LOGIN_SUCCEEDED)
        & APPID_SESSION_LOGIN_SUCCEEDED));
    delete ad;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

