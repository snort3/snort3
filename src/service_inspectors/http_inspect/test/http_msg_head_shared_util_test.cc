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

// http_msg_head_shared_util_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_msg_head_shared.h"
#include "service_inspectors/http_inspect/http_str_to_code.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

// Stubs whose sole purpose is to make the test code link
long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

// Tests for get_next_code()
TEST_GROUP(get_next_code)
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

TEST(get_next_code, basic)
{
    Field input(10, (const uint8_t*) "green,blue");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 6);
    CHECK(color == COLOR_GREEN);
    color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 11);
    CHECK(color == COLOR_BLUE);
}

TEST(get_next_code, single_token)
{
    Field input(6, (const uint8_t*) "purple");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_PURPLE);
}

TEST(get_next_code, unknown_token)
{
    Field input(14, (const uint8_t*) "madeup,red,red");
    Color color = (Color) HttpMsgHeadTest::get_next_code_test(input, offset, color_table);
    CHECK(offset == 7);
    CHECK(color == COLOR_OTHER);
}

TEST(get_next_code, null_token)
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

// Tests for boundary_present()
TEST_GROUP(boundary_present)
{
    // This allows access to test a protected static member function
    class HttpMsgHeadTest : public HttpMsgHeadShared
    {
    public:
        static bool boundary_present_test(const Field& field)
        {
            return HttpMsgHeadShared::boundary_present(field);
        }
    };
};

TEST(boundary_present, present)
{
    Field input(20, (const uint8_t*) "xxxxxboundary=cccccc");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, not_present)
{
    Field input(20, (const uint8_t*) "xxxxx123456789cccccc");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, equal_only)
{
    Field input(20, (const uint8_t*) "xxxxx12345=789cccccc");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, several_missing)
{
    Field input(16, (const uint8_t*) "123456b789ccry=c");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, b_missing)
{
    Field input(50, (const uint8_t*) "12345678901234567890oundary=9012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, equal_missing)
{
    Field input(50, (const uint8_t*) "12345678901234567890boundary9012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, d_missing)
{
    Field input(50, (const uint8_t*) "12345678901234567890bounxary=012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, front)
{
    Field input(50, (const uint8_t*) "boundary=01234567890123456789012345678901234567890");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, end)
{
    Field input(50, (const uint8_t*) "01234567890123456789012345678901234567890boundary=");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, front_edge_case)
{
    Field input(49, (const uint8_t*) "oundary=01234567890123456789012345678901234567890");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, whole_buffer)
{
    Field input(9, (const uint8_t*) "boundary=");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, all_upper)
{
    Field input(50, (const uint8_t*) "12345678901234567890BOUNDARY=012345678901234567890");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, mixed_case)
{
    Field input(50, (const uint8_t*) "12345678901234567890BoUnDaRy=012345678901234567890");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, false_starts)
{
    Field input(42, (const uint8_t*) "ARy=56789foundary=\0==ry=1234boundary=kkkkk");
    CHECK(HttpMsgHeadTest::boundary_present_test(input));
}

TEST(boundary_present, just_one_char)
{
    Field input(1, (const uint8_t*) "=");
    CHECK(!HttpMsgHeadTest::boundary_present_test(input));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

