//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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
// service_snmp_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <protocols/packet.h>
#include "../service_detector.h"

#include "../service_snmp.h"
#include "../service_snmp.cc"

#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

THREAD_LOCAL AppIdDebug* appidDebug = nullptr;
THREAD_LOCAL bool appid_trace_enabled = false;


TEST_GROUP(snmp_parsing_tests)
{
    void setup() override
    {
        
    }
    void teardown() override
    {
        
    }
};

TEST(snmp_parsing_tests, fail_on_invalid_sequence_tag)
{
    const uint8_t* data = (const uint8_t*)"\x31\x02\x01\x00"; /* Invalid tag - should be 0x30 */
    const uint8_t* end = data + 4;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

TEST(snmp_parsing_tests, fail_on_insufficient_data)
{
    const uint8_t* data = (const uint8_t*)"\x30"; /* Only sequence tag, no length */
    const uint8_t* end = data + 1;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

TEST(snmp_parsing_tests, fail_on_invalid_version_tag)
{
    const uint8_t* data = (const uint8_t*)"\x30\x05\x03\x01\x00\x04\x01"; /* Wrong version tag (0x03 instead of 0x02) */
    const uint8_t* end = data + 7;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

TEST(snmp_parsing_tests, fail_on_invalid_version_length)
{
    const uint8_t* data = (const uint8_t*)"\x30\x05\x02\x02\x00\x04\x01"; /* Version length should be 1, not 2 */
    const uint8_t* end = data + 7;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

TEST(snmp_parsing_tests, success_snmp_v1_packet)
{
    const uint8_t snmp_v1[] = "\x30\x1c\x02\x01\x00\x04\x06public\xa0\x0f\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x04\x30\x02\x06\x00";
    const uint8_t* data = snmp_v1;
    const uint8_t* end = data + sizeof(snmp_v1) - 1;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, 0);
    CHECK_EQUAL(version, 0); /* SNMP v1 */
    CHECK_EQUAL(pdu, 0); /* GET request */
}

TEST(snmp_parsing_tests, success_snmp_v2c_packet)
{
    const uint8_t snmp_v2c[] = "\x30\x1d\x02\x01\x01\x04\x06public\xa0\x10\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x05\x30\x03\x06\x01\x00";
    const uint8_t* data = snmp_v2c;
    const uint8_t* end = data + sizeof(snmp_v2c) - 1;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, 0);
    CHECK_EQUAL(version, 1); /* SNMP v2c */
    CHECK_EQUAL(pdu, 0); /* GET request */
}

TEST(snmp_parsing_tests, fail_on_invalid_community_string)
{
    const uint8_t* data = (const uint8_t*)"\x30\x0b\x02\x01\x00\x04\x04\xff\xfe\xfd\xfc\xa0\x00"; /* Non-printable community */
    const uint8_t* end = data + 13;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

TEST(snmp_parsing_tests, fail_on_unsupported_version)
{
    const uint8_t* data = (const uint8_t*)"\x30\x05\x02\x01\x05\x04\x00"; /* Version 5 (unsupported) */
    const uint8_t* end = data + 7;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

TEST(snmp_parsing_tests, fail_on_length_overflow)
{
    const uint8_t* data = (const uint8_t*)"\x30\x82\xff\xff"; /* Length field indicates more data than available */
    const uint8_t* end = data + 4;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

TEST(snmp_parsing_tests, fail_on_wrong_packet_length)
{
    const uint8_t* data = (const uint8_t*)"\x30\x7F"; /* SNMP packet with packet length = 127 */
    const uint8_t* end = data + 2;
    uint8_t pdu = 0;
    uint8_t version = 0;

    int ret = snmp_verify_packet(&data, end, &pdu, &version);
    CHECK_EQUAL(ret, -1);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}