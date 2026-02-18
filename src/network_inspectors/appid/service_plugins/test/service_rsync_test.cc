//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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

// service_rsync_test.cc author Steve Chew <stechew@cisco.com>
// unit test for service_rsync

#define RSYNC_UNIT_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../service_rsync.h"
#include "../service_rsync.cc"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

AppIdModule::AppIdModule() : Module("a", "b") { }
AppIdModule::~AppIdModule() = default;

static AppIdConfig test_config;
static ServiceDiscovery mock_sd;
static RsyncServiceDetector detector(&mock_sd);
static snort::Packet mock_pkt(false);
static snort::SfIp mock_ip;
static AppIdModule mock_module;

AppIdInspector::AppIdInspector(AppIdModule&) : config(&test_config), ctxt(test_config) { }

static AppIdInspector test_inspector(mock_module);
static OdpContext test_odp(test_config, nullptr);
static AppIdSession test_asd(IpProtocol::TCP, &mock_ip, 873, test_inspector, test_odp, 0, 0);

static ServiceRSYNCData* mock_rsync_data = nullptr;

AppIdFlowData* AppIdDetector::data_get(const AppIdSession&)
{
    return mock_rsync_data;
}

int AppIdDetector::data_add(AppIdSession&, AppIdFlowData* data)
{
    mock_rsync_data = static_cast<ServiceRSYNCData*>(data);
    return 0;
}

#define RSYNC_BANNER "@RSYNCD: "
#define RSYNC_BANNER_VALID       RSYNC_BANNER "26\n"
#define RSYNC_BANNER_NO_LINEFEED RSYNC_BANNER "26"
#define RSYNC_BANNER_BAD_VERSION RSYNC_BANNER "26a\n"
#define RSYNC_BANNER_INVALID     "INVALID: 26\n"
#define RSYNC_MOTD               "motd\n"
#define RSYNC_MOTD_NO_LINEFEED   "motd"
#define RSYNC_MOTD_INVALID_STR   "mo\x08td\n"

TEST_GROUP(service_rsync)
{
    void setup() override
    {
        mock_rsync_data = nullptr;
    }
    void teardown() override
    {
        delete mock_rsync_data;
        mock_rsync_data = nullptr;
    }
};

TEST(service_rsync, rsync_validate_zero_size)
{
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(nullptr, 0, APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_INPROCESS, ret);
}

TEST(service_rsync, rsync_validate_skip_data_from_client)
{
    uint8_t pkt[] = { 0x01 };
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args(pkt, sizeof(pkt), APP_ID_FROM_INITIATOR,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_INPROCESS, ret);
}

TEST(service_rsync, rsync_validate_banner_size_too_small)
{
    const char* data = "@RSYNC";
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
}

TEST(service_rsync, rsync_validate_banner_missing_linefeed)
{
    const char* data = RSYNC_BANNER_NO_LINEFEED;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
}

TEST(service_rsync, rsync_validate_banner_bad_version)
{
    const char* data = RSYNC_BANNER_BAD_VERSION;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
}

TEST(service_rsync, rsync_validate_banner_invalid_text)
{
    const char* data = RSYNC_BANNER_INVALID;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
}

TEST(service_rsync, rsync_validate_banner_valid)
{
    const char* data = RSYNC_BANNER_VALID;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_INPROCESS, ret);
    CHECK(mock_rsync_data != nullptr);
    CHECK_EQUAL(RSYNC_STATE_MOTD, mock_rsync_data->state);
}

TEST(service_rsync, rsync_validate_motd_no_linefeed)
{
    mock_rsync_data = new ServiceRSYNCData;
    mock_rsync_data->state = RSYNC_STATE_MOTD;

    const char* data = RSYNC_MOTD_NO_LINEFEED;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
    CHECK_EQUAL(RSYNC_STATE_MOTD, mock_rsync_data->state);
}

TEST(service_rsync, rsync_validate_motd_invalid_str)
{
    mock_rsync_data = new ServiceRSYNCData;
    mock_rsync_data->state = RSYNC_STATE_MOTD;

    const char* data = RSYNC_MOTD_INVALID_STR;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_NOMATCH, ret);
    CHECK_EQUAL(RSYNC_STATE_MOTD, mock_rsync_data->state);
}

TEST(service_rsync, rsync_validate_motd_valid)
{
    mock_rsync_data = new ServiceRSYNCData;
    mock_rsync_data->state = RSYNC_STATE_MOTD;

    const char* data = RSYNC_MOTD;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_SUCCESS, ret);
    CHECK_EQUAL(RSYNC_STATE_DONE, mock_rsync_data->state);
}

// It's an error to get another call to rsync_validate if we've
// already reached the DONE state.
TEST(service_rsync, rsync_validate_should_not_called_after_done)
{
    // Start in MOTD state (like after successful banner)
    mock_rsync_data = new ServiceRSYNCData;
    mock_rsync_data->state = RSYNC_STATE_MOTD;

    const char* data = RSYNC_MOTD;
    AppidChangeBits change_bits;
    AppIdDiscoveryArgs args((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits);

    // First call should succeed and move to DONE state
    int ret = detector.validate(args);
    CHECK_EQUAL(APPID_SUCCESS, ret);
    CHECK_EQUAL(RSYNC_STATE_DONE, mock_rsync_data->state);

    // Second call should fail because we're in DONE state
    AppidChangeBits change_bits2;
    AppIdDiscoveryArgs args2((const uint8_t*)data, strlen(data), APP_ID_FROM_RESPONDER,
        test_asd, &mock_pkt, change_bits2);

    ret = detector.validate(args2);
    CHECK_EQUAL(APPID_NOMATCH, ret);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
