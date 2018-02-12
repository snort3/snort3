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

// service_rsync_test.cc author Steve Chew <stechew@cisco.com>
// unit test for service_rsync

// FIXIT-M - unit tests disabled until mocking support can be figured out

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if 0
#include "appid_api.h"
#include "application_ids.h"

#include "service_plugin_mocks.h"
#include "network_inspectors/appid/service_plugins/service_rsync.cc"
#include "service_plugin_mocks.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

ServiceRSYNCData* fake_rsync_data = NULL;

TEST_GROUP(service_rsync)
{
    void setup()
    {
        fake_rsync_data = NULL;
    }

    void teardown()
    {
        snort_free(fake_rsync_data);
        mock().clear();
    }
};

TEST(service_rsync, rsync_validate_zero_size)
{
    AppIdDiscoveryArgs args;
    args.size = 0;

    mock().expectOneCall("service_inprocess");
    LONGS_EQUAL(APPID_INPROCESS, rsync_validate(&args));
    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_skip_data_from_client)
{
    AppIdDiscoveryArgs args;
    args.size = 1;
    args.dir  = APP_ID_FROM_INITIATOR;
    rsync_service_mod.api = &fake_serviceapi;

    mock().expectOneCall("service_inprocess");
    LONGS_EQUAL(APPID_INPROCESS, rsync_validate(&args));
    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_no_rsync_data_size_too_small)
{
    AppIdDiscoveryArgs args;
    args.size = 1;
    args.dir  = APP_ID_FROM_RESPONDER;
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(APPID_NOMATCH, rsync_validate(&args));

    mock().checkExpectations();
}

#define RSYNC_BANNER_VALID       RSYNC_BANNER "26\n"
#define RSYNC_BANNER_NO_LINEFEED RSYNC_BANNER "26"
#define RSYNC_BANNER_BAD_VERSION RSYNC_BANNER "26a\n"
#define RSYNC_BANNER_INVALID     "INVALID: 26\n"
#define RSYNC_MOTD             "motd\n"
#define RSYNC_MOTD_NO_LINEFEED "motd"
#define RSYNC_MOTD_INVALID_STR "mo\btd\n"

TEST(service_rsync, rsync_validate_banner_missing_linefeed)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_NO_LINEFEED;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(APPID_NOMATCH, rsync_validate(&args));

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_banner_bad_version)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_BAD_VERSION;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(APPID_NOMATCH, rsync_validate(&args));

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_banner_invalid_text)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_INVALID;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(APPID_NOMATCH, rsync_validate(&args));

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_banner_valid)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_VALID;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("service_inprocess");

    LONGS_EQUAL(APPID_INPROCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_MOTD, fake_rsync_data->state);

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_motd_no_linefeed)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD_NO_LINEFEED;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(APPID_NOMATCH, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_MOTD, fake_rsync_data->state);

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_motd_invalid_str)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD_INVALID_STR;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(APPID_NOMATCH, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_MOTD, fake_rsync_data->state);

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_motd_valid)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("add_service");

    LONGS_EQUAL(APPID_SUCCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_DONE, fake_rsync_data->state);

    mock().checkExpectations();
}

//  It's an error to get another call to rsync_validate if we've
//  already reached the DONE state.
TEST(service_rsync, rsync_validate_should_not_called_after_done)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("add_service");
    mock().expectOneCall("data_get");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(APPID_SUCCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_DONE, fake_rsync_data->state);

    LONGS_EQUAL(APPID_NOMATCH, rsync_validate(&args));
    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_count_rsync_flow_on_success)
{
    AppIdDiscoveryArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD;
    args.size = strlen((const char*)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("add_service");

    LONGS_EQUAL(APPID_SUCCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_DONE, fake_rsync_data->state);
    LONGS_EQUAL(1, appid_stats.rsync_flows);

    mock().checkExpectations();
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
#endif

int main(int, char**)
{

}
