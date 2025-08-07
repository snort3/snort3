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
// service_netbios_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../service_netbios.h"
#include "../service_netbios.cc"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

void AppIdSessionApi::set_netbios_name(AppidChangeBits& change_bits, const char* name) { }

TEST_GROUP(netbios_parsing_tests)
{
    void setup() override
    {
        
    }
    void teardown() override
    {
        
    }
};

TEST(netbios_parsing_tests, netbios_parse_invalid_len_missing_position)
{
    const uint8_t* data = (const uint8_t*)"\xC0"; // Invalid length
    const uint8_t* original_data = data;
    const uint8_t* end = data + 1;
    char name[NBNS_NAME_LEN / 2 + 1] = {0};

    int ret = netbios_validate_name_and_decode(&data, data, end, name);
    CHECK_EQUAL(-1, ret);
    CHECK_EQUAL(data, original_data); // Ensure data pointer is unchanged
}

TEST(netbios_parsing_tests, netbios_parse_invalid_len_wrong_position)
{
    const uint8_t* data = (const uint8_t*)"\xC0\xFF"; // Invalid length
    const uint8_t* original_data = data;
    const uint8_t* end = data + 2;
    char name[NBNS_NAME_LEN / 2 + 1] = {0};

    int ret = netbios_validate_name_and_decode(&data, data, end, name);
    CHECK_EQUAL(-1, ret);
    CHECK_EQUAL(original_data + sizeof(NBNSLabelPtr), data); // Check that length and flags are parsed
}

TEST(netbios_parsing_tests, netbios_parse_invalid_len_missing_position_without_decode)
{
    const uint8_t* data = (const uint8_t*)"\xC0"; // Invalid length
    const uint8_t* original_data = data;
    const uint8_t* end = data + 1;
    char name[NBNS_NAME_LEN / 2 + 1] = {0};

    int ret = netbios_validate_name(&data, data, end);
    CHECK_EQUAL(-1, ret);
    CHECK_EQUAL(data, original_data); // Ensure data pointer is unchanged
}

TEST(netbios_parsing_tests, netbios_parse_invalid_len_wrong_position_without_decode)
{
    const uint8_t* data = (const uint8_t*)"\xC0\xFF"; // Invalid length
    const uint8_t* original_data = data;
    const uint8_t* end = data + 2;
    char name[NBNS_NAME_LEN / 2 + 1] = {0};

    int ret = netbios_validate_name(&data, data, end);
    CHECK_EQUAL(-1, ret);
    CHECK_EQUAL(original_data + sizeof(NBNSLabelPtr), data); // Check that length and flags are parsed
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
