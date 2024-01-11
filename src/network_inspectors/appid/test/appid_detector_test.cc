//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "appid_mock_definitions.h"
#include "appid_mock_http_session.h"
#include "appid_mock_inspector.h"
#include "appid_mock_session.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

namespace snort
{
AppIdSessionApi::AppIdSessionApi(const AppIdSession*, const SfIp&) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID) {}
}

void ApplicationDescriptor::set_id(
    const Packet&, AppIdSession&, AppidSessionDirection, AppId, AppidChangeBits&) { }

void AppIdHttpSession::set_http_change_bits(AppidChangeBits&, HttpFieldIds) {}

void AppIdModule::reset_stats() {}

class TestDetector : public AppIdDetector
{
public:
    TestDetector() = default;

    void do_custom_init() override { }
    void do_custom_reload() override { }
    int validate(AppIdDiscoveryArgs&) override { return 0; }
    void register_appid(AppId, unsigned, OdpContext&) override { }
};

TEST_GROUP(appid_detector_tests)
{
    Flow* flow = nullptr;
    AppIdSession* mock_session = nullptr;

    void setup() override
    {
        SfIp ip;
        mock_session = new AppIdSession(IpProtocol::TCP, &ip, 1492, dummy_appid_inspector,
            dummy_appid_inspector.get_ctxt().get_odp_ctxt(), 0, 0);
        flow = new Flow;
        flow->set_flow_data(mock_session);
    }

    void teardown() override
    {
        delete flow;
        delete &mock_session->get_api();
        delete mock_session;
    }
};

TEST(appid_detector_tests, add_user)
{
    const char* username = "snorty";
    AppIdDetector* ad = new TestDetector;
    AppidChangeBits cb;
    ad->add_user(*mock_session, username, APPID_UT_ID, true, cb);
    STRCMP_EQUAL(mock_session->get_client_user(), username);
    CHECK_TRUE((mock_session->get_client_user_id() == APPID_UT_ID));
    delete ad;
}

TEST(appid_detector_tests, get_code_string)
{
    AppIdDetector* ad = new TestDetector;
    STRCMP_EQUAL(ad->get_code_string(APPID_SUCCESS), "success");
    STRCMP_EQUAL(ad->get_code_string(APPID_INPROCESS), "in-process");
    STRCMP_EQUAL(ad->get_code_string(APPID_NEED_REASSEMBLY), "need-reassembly");
    STRCMP_EQUAL(ad->get_code_string(APPID_NOT_COMPATIBLE), "not-compatible");
    STRCMP_EQUAL(ad->get_code_string(APPID_INVALID_CLIENT), "invalid-client");
    STRCMP_EQUAL(ad->get_code_string(APPID_REVERSED), "appid-reversed");
    STRCMP_EQUAL(ad->get_code_string(APPID_NOMATCH), "no-match");
    STRCMP_EQUAL(ad->get_code_string(APPID_ENULL), "error-null");
    STRCMP_EQUAL(ad->get_code_string(APPID_EINVALID), "error-invalid");
    STRCMP_EQUAL(ad->get_code_string(APPID_ENOMEM), "error-memory");
    STRCMP_EQUAL(ad->get_code_string(APPID_SUCCESS), "success");
    STRCMP_EQUAL(ad->get_code_string((APPID_STATUS_CODE)123), "unknown-code");
    delete ad;
}

int main(int argc, char** argv)
{
    mock_init_appid_pegs();
    int rc = CommandLineTestRunner::RunAllTests(argc, argv);
    mock_cleanup_appid_pegs();
    return rc;
}

