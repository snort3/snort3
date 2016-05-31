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

// nhttp_normalizers_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#include "service_inspectors/nhttp_inspect/nhttp_msg_header.h"
#include "service_inspectors/nhttp_inspect/nhttp_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

// Stubs whose sole purpose is to make the test code link
int32_t str_to_code(const uint8_t*, const int32_t, const StrCode []) { return 0; }
const bool NHttpEnums::is_sp_tab[256] {};
long NHttpTestManager::print_amount {};
bool NHttpTestManager::print_hex {};

TEST_GROUP(nhttp_chunked_before_end_test) {};

TEST(nhttp_chunked_before_end_test, examples)
{
    CHECK(!chunked_before_end(Field(11, (const uint8_t*)"foo,chunked")));
    CHECK(chunked_before_end(Field(15, (const uint8_t*)"chunked,chunked")));
    CHECK(!chunked_before_end(Field(10, (const uint8_t*)"notchunked")));
    CHECK(chunked_before_end(Field(12, (const uint8_t*)"foo,chunked,")));
    CHECK(chunked_before_end(Field(16, (const uint8_t*)"chunked,identity")));
    CHECK(chunked_before_end(Field(21, (const uint8_t*)"gzip,chunked,identity")));
    CHECK(!chunked_before_end(Field(0, (const uint8_t*)"")));
    CHECK(!chunked_before_end(Field(7, (const uint8_t*)"chunked")));
    CHECK(!chunked_before_end(Field(8, (const uint8_t*)",chunked")));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

