//--------------------------------------------------------------------------
// Copyright (C) 2016 Cisco and/or its affiliates. All rights reserved.
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

// http_msg_head_shared_util_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#include "service_inspectors/http_inspect/http_msg_head_shared.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_str_to_code.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

// Stubs whose sole purpose is to make the test code link
long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

TEST_GROUP(http_msg_head_shared_util)
{
    enum Color { COLOR_OTHER=1, COLOR_GREEN, COLOR_BLUE, COLOR_RED, COLOR_YELLOW, COLOR_PURPLE };
    int32_t offset = 0;
    const StrCode color_table[6] =
    {
        { COLOR_GREEN,  "green" },
        { COLOR_BLUE,   "blue" },
        { COLOR_RED,    "red" },
        { COLOR_YELLOW, "yellow" },
        { COLOR_PURPLE, "purple" },
        { 0,            nullptr }
    };

    // This allows access to test a protected static member function
    class HttpMsgHeadTest : public HttpMsgHeadShared
    {
    public:
        static int32_t get_next_code_test(const Field& field, int32_t& offset,
            const StrCode table[])
        {
            return HttpMsgHeadShared::get_next_code(field, offset, table);
        }
    };
};

TEST(http_msg_head_shared_util, basic)
{
    Field input(10, (const uint8_t*) "green,blue");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 6);
    CHECK(color == COLOR_GREEN);
    color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 11);
    CHECK(color == COLOR_BLUE);
}

TEST(http_msg_head_shared_util, single_token)
{
    Field input(6, (const uint8_t*) "purple");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_PURPLE);
}

TEST(http_msg_head_shared_util, unknown_token)
{
    Field input(14, (const uint8_t*) "madeup,red,red");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_OTHER);
}

TEST(http_msg_head_shared_util, null_token)
{
    Field input(11, (const uint8_t*) "green,,blue");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 6);
    CHECK(color == COLOR_GREEN);
    color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_OTHER);
    color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 12);
    CHECK(color == COLOR_BLUE);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

