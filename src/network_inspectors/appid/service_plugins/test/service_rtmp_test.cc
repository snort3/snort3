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
// service_rtmp_test.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../service_rtmp.h"
#include "../service_rtmp.cc"
#include "service_plugin_mock.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

TEST_GROUP(rtmp_parsing_tests)
{
    void setup() override
    {
        
    }
    void teardown() override
    {
        
    }
};

TEST(rtmp_parsing_tests, rtmp_parse_invalid_len)
{
    const uint8_t* data = (const uint8_t*)"\x41\x00";
    uint16_t size = 2;
    uint8_t format = 0;
    uint32_t chunk_stream_id = 0;

    int ret = parse_rtmp_chunk_basic_header(&data, &size, &format, &chunk_stream_id);
    CHECK_EQUAL(0, ret);
    CHECK_EQUAL(2, size);
    CHECK_EQUAL(1, chunk_stream_id);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
