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

// http_normalizers_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_normalizers.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;
using namespace HttpEnums;

// Stubs whose sole purpose is to make the test code link
const bool HttpEnums::is_sp_tab[256] {};
const bool HttpEnums::is_sp_tab_quote_dquote[256] {};
long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

TEST_GROUP(norm_decimal_integer_test) {};

TEST(norm_decimal_integer_test, examples)
{
    CHECK(norm_decimal_integer(Field(1, (const uint8_t*)"0")) == 0);
    CHECK(norm_decimal_integer(Field(2, (const uint8_t*)"27")) == 27);
    CHECK(norm_decimal_integer(Field(5, (const uint8_t*)"00027")) == 27);
    CHECK(norm_decimal_integer(Field(2, (const uint8_t*)"-27")) == STAT_PROBLEMATIC);
    CHECK(norm_decimal_integer(Field(6, (const uint8_t*)"27,382")) == 27);
    CHECK(norm_decimal_integer(Field(3, (const uint8_t*)",27")) == STAT_PROBLEMATIC);
    CHECK(norm_decimal_integer(Field(6, (const uint8_t*)"00000=")) == STAT_PROBLEMATIC);
    CHECK(norm_decimal_integer(Field(6, (const uint8_t*)"32.578")) == STAT_PROBLEMATIC);
    CHECK(norm_decimal_integer(Field(18, (const uint8_t*)"123456789012345678")) ==
        123456789012345678);
    CHECK(norm_decimal_integer(Field(19, (const uint8_t*)"1234567890123456789")) ==
        STAT_PROBLEMATIC);
    CHECK(norm_decimal_integer(Field(19, (const uint8_t*)"0123456789012345678")) ==
        123456789012345678);
    CHECK(norm_decimal_integer(Field(20, (const uint8_t*)"01234567890123456789")) ==
        STAT_PROBLEMATIC);
    CHECK(norm_decimal_integer(Field(25, (const uint8_t*)"0000000000000000000000027")) == 27);
    CHECK(norm_decimal_integer(Field(8, (const uint8_t*)"0040E,27")) == STAT_PROBLEMATIC);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

