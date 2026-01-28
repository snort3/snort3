//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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
// iec104_parse_apdu_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#include <unordered_map>
#include <vector>

#include "../iec104_parse_apdu.cc"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

int snort::DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }

TEST_GROUP(iec104_parse_apdu_invalid_packet_len)
{
};

const uint8_t test_data_1[] = {0x68, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x03, 0x01, 0x00, 0x00};
const uint8_t test_data_2[] = {0x68, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x01, 0x00, 0x00};

const uint8_t test_data_m_me_nc_1_sq0[] = {
    0x68, 0x6f, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x0e, 0x01, 0x00, 0x01, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 0x01, 0x00, 0x00, 0x00, 
    0x00, 0x80, 0x3f, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 
    0x03, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 0x04, 0x00, 0x00, 0x00, 
    0x00, 0x80, 0x3f, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 
    0x06, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 0x07, 0x00, 0x00, 0x00, 
    0x00, 0x80, 0x3f, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 
    0x09, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 0x0a, 0x00, 0x00, 0x00, 
    0x00, 0x80, 0x3f, 0x10, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f, 0x10, 0x0d, 0x00, 0x00, 0x00, 
    0x00, 0x80, 0x3f, 0x10
};

const uint8_t test_data_m_me_tc_1_sq0[] = {0x68, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x24, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01};

const uint8_t test_data_m_me_tf_1_sq0[] = {0x68, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x28, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01};

TEST(iec104_parse_apdu_invalid_packet_len, invalid_group_data)
{
    static bool result = true;
    genericGroupPtr = [](const void* genericIOGroup)
    {
        if (result)
        {
            result = genericIOGroup == nullptr;
        }
    };
    
    for(uint32_t i = 0; i < 128; i++)
    {
        parseIec104GenericAsdu(i, (const Iec104ApciI*)test_data_1, sizeof(test_data_1));
        parseIec104GenericAsdu(i, (const Iec104ApciI*)test_data_2, sizeof(test_data_2));
    }
    CHECK_EQUAL(true, result);
}

TEST(iec104_parse_apdu_invalid_packet_len, m_me_nc_1_sq0_bounds_check)
{
    static bool result = true;
    genericGroupPtr = [](const void* genericIOGroup)
    {
        if (result)
        {
            result = genericIOGroup == nullptr;
        }
    };
    
    for(uint32_t i = 0; i < 128; i++)
    {
        parseIec104GenericAsdu(i, (const Iec104ApciI*)test_data_m_me_nc_1_sq0, sizeof(test_data_m_me_nc_1_sq0));
    }
    CHECK_EQUAL(true, result);
}

TEST(iec104_parse_apdu_invalid_packet_len, m_me_tc_1_sq0_bounds_check)
{
    static bool result = true;
    genericGroupPtr = [](const void* genericIOGroup)
    {
        if (result)
        {
            result = genericIOGroup == nullptr;
        }
    };
    
    for(uint32_t i = 0; i < 128; i++)
    {
        parseIec104GenericAsdu(i, (const Iec104ApciI*)test_data_m_me_tc_1_sq0, sizeof(test_data_m_me_tc_1_sq0));
    }
    CHECK_EQUAL(true, result);
}

TEST(iec104_parse_apdu_invalid_packet_len, m_me_tf_1_sq0_bounds_check)
{
    static bool result = true;
    genericGroupPtr = [](const void* genericIOGroup)
    {
        if (result)
        {
            result = genericIOGroup == nullptr;
        }
    };
    
    for(uint32_t i = 0; i < 128; i++)
    {
        parseIec104GenericAsdu(i, (const Iec104ApciI*)test_data_m_me_tf_1_sq0, sizeof(test_data_m_me_tf_1_sq0));
    }
    CHECK_EQUAL(true, result);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}