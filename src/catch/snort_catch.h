//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

// snort_catch.h author Carter Waxman <cwaxman@cisco.com>

#ifndef SNORT_CATCH_H
#define SNORT_CATCH_H

// This header adds a wrapper around Catch to facilitate testing in dynamic
// modules. Because of quirks in global storage (as used by Catch), an
// installer in the main binary is necessary to access Catch's global state and
// provide test cases from dynamic plugins to the global list of tests to be
// run. This header should be used instead of including catch.hpp directly.

// pragma for running unit tests on dynamic modules
#pragma GCC visibility push(default)
#include "catch.hpp"
#pragma GCC visibility pop

#include "main/snort_types.h"

namespace snort
{
class TestCaseInstaller
{
public:
    SO_PUBLIC TestCaseInstaller(void(*fun)(), const char* name);
    SO_PUBLIC TestCaseInstaller(void(*fun)(), const char* name, const char* group);
};

/*  translate this:
        SNORT_TEST_CASE("my_test", "[snort_tests"])
        {
            REQUIRE(true);
        }

    to this:
        static void snort_test1();
        static TestCaseInstaller test_test_installer1(snort_test1, "my_test", "[snort_tests]");
        static void snort_test1()
        {
            REQUIRE(true);
        }
*/
#define MAKE_SNORT_TEST_CASE(fun, ...) \
    static void fun(); \
    static snort::TestCaseInstaller INTERNAL_CATCH_UNIQUE_NAME(test_case_installer)(fun, __VA_ARGS__); \
    static void fun()

#undef TEST_CASE
#define TEST_CASE(...) MAKE_SNORT_TEST_CASE(INTERNAL_CATCH_UNIQUE_NAME(snort_test), __VA_ARGS__)
}

#endif
