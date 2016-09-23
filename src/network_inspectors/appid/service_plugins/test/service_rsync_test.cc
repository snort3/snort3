//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "network_inspectors/appid/service_plugins/service_rsync.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void Debug::print(const char*, int, uint64_t, const char*, ...) { }

extern int rsync_validate(ServiceValidationArgs*);

int fake_service_inprocess(AppIdSession*, const Packet*, int, const RNAServiceElement*)
{
    mock().actualCall("service_inprocess");
    return -1;
}

ServiceRSYNCData* fake_rsync_data = NULL;

void* fake_service_flowdata_get(AppIdSession*, unsigned)
{
    mock().actualCall("data_get");
    return fake_rsync_data;
}

int fake_data_add(AppIdSession*, void* data, unsigned, AppIdFreeFCN)
{
    mock().actualCall("data_add");
    fake_rsync_data = (ServiceRSYNCData*)data;
    return -1;
}

int fake_fail_service(AppIdSession*, const Packet*, int, const RNAServiceElement*, unsigned, const AppIdConfig*)
{
    mock().actualCall("fail_service");
    return -1;
}

int fake_add_service(AppIdSession*, const Packet*, int,
    const RNAServiceElement*, AppId, const char*, const char *,
    const RNAServiceSubtype*)
{
    mock().actualCall("add_service");
    return -1;
}

const ServiceApi fake_serviceapi =
{
    &fake_service_flowdata_get,
    &fake_data_add,
    nullptr,
    nullptr,
    nullptr,
    &fake_add_service,
    &fake_fail_service,
    &fake_service_inprocess,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
};

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

TEST(service_rsync, rsync_validate_null_args)
{
    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(nullptr));
}

TEST(service_rsync, rsync_validate_zero_size)
{
    ServiceValidationArgs args;
    args.size = 0;
    rsync_service_mod.api = &fake_serviceapi;

    mock().expectOneCall("service_inprocess");
    LONGS_EQUAL(SERVICE_INPROCESS, rsync_validate(&args));
    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_skip_data_from_client)
{
    ServiceValidationArgs args;
    args.size = 1;
    args.dir  = APP_ID_FROM_INITIATOR;
    rsync_service_mod.api = &fake_serviceapi;

    mock().expectOneCall("service_inprocess");
    LONGS_EQUAL(SERVICE_INPROCESS, rsync_validate(&args));
    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_no_rsync_data_size_too_small)
{
    ServiceValidationArgs args;
    args.size = 1;
    args.dir  = APP_ID_FROM_RESPONDER;
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(&args));

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
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_NO_LINEFEED;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(&args));

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_banner_bad_version)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_BAD_VERSION;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(&args));

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_banner_invalid_text)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_INVALID;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(&args));

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_banner_valid)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_BANNER_VALID;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("data_add");
    mock().expectOneCall("service_inprocess");

    LONGS_EQUAL(SERVICE_INPROCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_MOTD, fake_rsync_data->state);

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_motd_no_linefeed)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD_NO_LINEFEED;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_MOTD, fake_rsync_data->state);

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_motd_invalid_str)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD_INVALID_STR;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_MOTD, fake_rsync_data->state);

    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_motd_valid)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("add_service");

    LONGS_EQUAL(SERVICE_SUCCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_DONE, fake_rsync_data->state);

    mock().checkExpectations();
}

//  It's an error to get another call to rsync_validate if we've
//  already reached the DONE state.
TEST(service_rsync, rsync_validate_should_not_called_after_done)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("add_service");
    mock().expectOneCall("data_get");
    mock().expectOneCall("fail_service");

    LONGS_EQUAL(SERVICE_SUCCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_DONE, fake_rsync_data->state);

    LONGS_EQUAL(SERVICE_NOMATCH, rsync_validate(&args));
    mock().checkExpectations();
}

TEST(service_rsync, rsync_validate_count_rsync_flow_on_success)
{
    ServiceValidationArgs args;
    args.dir  = APP_ID_FROM_RESPONDER;
    args.data = (const uint8_t*)RSYNC_MOTD;
    args.size = strlen((const char *)args.data);
    rsync_service_mod.api = &fake_serviceapi;

    fake_rsync_data = (ServiceRSYNCData*)snort_calloc(sizeof(ServiceRSYNCData));
    fake_rsync_data->state = RSYNC_STATE_MOTD;

    mock().strictOrder();
    mock().expectOneCall("data_get");
    mock().expectOneCall("add_service");

    LONGS_EQUAL(SERVICE_SUCCESS, rsync_validate(&args));
    LONGS_EQUAL(RSYNC_STATE_DONE, fake_rsync_data->state);
    LONGS_EQUAL(1, appid_stats.rsync_flows);

    mock().checkExpectations();
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

