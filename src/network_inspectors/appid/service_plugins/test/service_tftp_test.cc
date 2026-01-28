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
// service_tftp_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define TFTP_UNIT_TEST

#include "../service_tftp.h"
#include "../service_tftp.cc"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

AppIdModule::AppIdModule()
    : Module("a", "b") { }
AppIdModule::~AppIdModule() = default;

THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
THREAD_LOCAL bool appid_trace_enabled = false;

static ServiceDiscovery test_service_discovery;
AppIdConfig test_app_config;
AppIdInspector::AppIdInspector(AppIdModule&) : config(&test_app_config), ctxt(test_app_config) { }

ServiceTFTPData* test_data_get = nullptr;

AppIdFlowData* AppIdDetector::data_get(const AppIdSession&)
{
    return test_data_get;
}

TEST_GROUP(tftp_parsing_tests)
{
    TftpServiceDetector* test_detector = nullptr;
    void setup() override
    {
        test_detector = new TftpServiceDetector(&test_service_discovery);
    }
    void teardown() override
    {
        delete test_detector;
        test_detector = nullptr;
    }
};

TEST(tftp_parsing_tests, validate_packet_with_non_null_terminated_data)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    AppIdSession test_asd(IpProtocol::UDP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    const uint8_t test_data[] = {0x00, 0x02, 0x53, 0x53, 0x53, 0x53, 0x53, 0x53};
    uint16_t test_data_size = 8;
    AppidChangeBits cb;

    test_data_get = new ServiceTFTPData(TFTP_STATE_CONNECTION);

    AppIdDiscoveryArgs test_args(test_data, test_data_size, AppidSessionDirection::APP_ID_FROM_INITIATOR, test_asd, nullptr, cb);

    auto result = test_detector->validate(test_args);
    CHECK_EQUAL(APPID_NOT_COMPATIBLE, result);

    delete &test_asd.get_api();
    delete test_data_get;
    test_data_get = nullptr;
}

TEST(tftp_parsing_tests, validate_packet_from_ack_to_success)
{
    OdpContext test_odp_ctxt(test_app_config, nullptr);
    AppIdModule test_module;
    AppIdInspector test_inspector(test_module);
    AppIdSession test_asd(IpProtocol::UDP, nullptr, (uint16_t)0, test_inspector, test_odp_ctxt, (uint32_t)0, 0);
    const uint8_t test_data[] = {0x00, 0x04, 0x00, 0x01};
    uint16_t test_data_size = 4;
    AppidChangeBits cb;

    test_data_get = new ServiceTFTPData(TFTP_STATE_ACK);

    AppIdDiscoveryArgs test_args(test_data, test_data_size, AppidSessionDirection::APP_ID_FROM_RESPONDER, test_asd, nullptr, cb);

    auto result = test_detector->validate(test_args);
    CHECK_EQUAL(APPID_SUCCESS, result);
    CHECK_EQUAL(1, test_data_get->count);

    delete &test_asd.get_api();
    delete test_data_get;
    test_data_get = nullptr;
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_incorrect_len)
{
    const uint8_t data[] = {0x00};
    const uint16_t size = 1;
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(-1, result);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_data_incorrect_len)
{
    const uint8_t data[] = {0x00, 0x03, 0x00, 0x01};
    const uint16_t size = 518; 
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(-1, result);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_data)
{
    const uint8_t data[] = {0x00, 0x03, 0x00, 0x02}; 
    const uint16_t size = 4; 
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(TFTP_STATE_DATA, result);
    CHECK_EQUAL(2, block);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_ack_incorrect_len)
{
    const uint8_t data[] = {0x00, 0x04, 0x00, 0x00, 0x00}; 
    const uint16_t size = 5;
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(-1, result);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_ack)
{
    const uint8_t data[] = {0x00, 0x04, 0x00, 0x05}; 
    const uint16_t size = 4;
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(TFTP_STATE_ACK, result);
    CHECK_EQUAL(5, block);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_error_incorrect_len)
{
    const uint8_t data[] = {0x00, 0x05, 0x00, 0x01}; 
    const uint16_t size = 4; 
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(-1, result);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_error_invalid_code)
{
    const uint8_t data[] = {0x00, 0x05, 0x00, 0x08, 0x12}; 
    const uint16_t size = 5;
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(-1, result);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_error_non_null_terminated)
{
    const uint8_t data[] = {0x00, 0x05, 0x00, 0x03, 0xFF, 0xFF}; 
    const uint16_t size = 6; 
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(-1, result);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_error)
{
    const uint8_t data[] = {0x00, 0x05, 0x00, 0x03, 0x00}; 
    const uint16_t size = 5; 
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(TFTP_STATE_ERROR, result);
}

TEST(tftp_parsing_tests, tftp_verify_header_opcode_unknown)
{
    const uint8_t data[] = {0x00, 0x09, 0x00, 0x01}; 
    const uint16_t size = 4; 
    uint16_t block = 0;
    
    auto result = tftp_verify_header(data, size, &block);
    CHECK_EQUAL(-1, result);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}