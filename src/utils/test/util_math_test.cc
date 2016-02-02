//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// util_math_test.cc author Russ Combs <rucombs@cisco.com>
// unit test main

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "utils/util_math.h"

TEST_GROUP(util_math) { };

TEST(util_math, percent)
{
    CHECK(calc_percent(1.0, 1.0) == 100.0);
    CHECK(calc_percent(1.0, 2.0) ==  50.0);
    CHECK(calc_percent(1.0, 8.0) ==  12.5);

    CHECK(calc_percent(1, 1) == 100.0);
    CHECK(calc_percent(1, 2) ==  50.0);
    CHECK(calc_percent(1, 8) ==  12.5);

    CHECK(calc_percent(1, 0) ==  0);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

