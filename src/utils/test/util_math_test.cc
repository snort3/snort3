// main.cc author Russ Combs <rucombs@cisco.com>
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

