//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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
//
// service_ftp_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#define FTP_UNIT_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../service_ftp.h"
#include "../service_ftp.cc"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

const uint8_t* service_strstr(const uint8_t* p, unsigned,
    const uint8_t*, unsigned)
{
    return nullptr;
}

AppIdModule::AppIdModule()
    : Module("a", "b") { }
AppIdModule::~AppIdModule() = default;

AppIdConfig test_app_config;

static ServiceFTPData mock_service_data;
static ServiceDiscovery mock_service_discovery;
static FtpServiceDetector test_detector(&mock_service_discovery);

AppIdInspector::AppIdInspector(AppIdModule&) : config(&test_app_config), ctxt(test_app_config) { }

AppIdFlowData* AppIdDetector::data_get(const AppIdSession&)
{
    return &mock_service_data;
}

TEST_GROUP(ftp_parsing_tests)
{
    void setup() override
    {
        
    }
    void teardown() override
    {
        
    }
};

TEST(ftp_parsing_tests, ftp_parse_invalid_offset_reply)
{
    uint8_t* data = new uint8_t[65535];
    uint16_t offset = 65530;
    ServiceFTPData fd;
    fd.rstate = FTP_REPLY_MULTI;

    memset(data, 0, 65535);
    data[65534] = 0x0D;
    data[65533] = 0x0D;

    auto res = ftp_validate_reply(data, offset, 65535, fd);
    CHECK_EQUAL(0, res);
    delete[] data;
}

TEST(ftp_parsing_tests, ftp_parse_invalid_offset_response)
{
    uint8_t* data = new uint8_t[65535];
    uint16_t offset = 65533;
    ServiceFTPData fd;
    fd.rstate = FTP_REPLY_MULTI;

    memset(data, 0, 65535);
    data[65534] = 0x0D;
    data[65533] = 0x0D;
    data[65532] = 0x0D;

    auto res = ftp_parse_response(data, offset, 65535, fd, FTP_REPLY_MULTI);
    CHECK_EQUAL(FTP_PARTIAL_EOL, res);

    offset = 65534;
    memset(data, 0, 65535);
    res = ftp_parse_response(data, offset, 65535, fd, FTP_REPLY_MULTI);
    CHECK_EQUAL(FTP_NOT_FOUND_EOL, res);

    delete[] data;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}