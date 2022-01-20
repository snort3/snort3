//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// boyer_moore_test.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../boyer_moore.h"

#include <algorithm>
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTestExt/MockSupport.h>
#include <CppUTest/TestHarness.h>
#include <string>

using namespace std;
using namespace snort;

enum TestType
{
    CASE,
    NOCASE,
};

class Tester
{
public:
    Tester(const char* pat_str, const char* buf_str, TestType typ, int idx)
        : pat(pat_str), buf(buf_str), type(typ), index(idx)
    {
        if ( type == NOCASE )
            transform(pat.begin(), pat.end(), pat.begin(), ::toupper);

        pattern_len = pat.length();
        buffer_len = buf.length();

        pattern = (const uint8_t*)(pat.c_str());
        buffer = (const uint8_t*)(buf.c_str());
    }

    bool run();

private:
    string pat;
    string buf;

    TestType type;

    int index;

    unsigned pattern_len;
    unsigned buffer_len;

    const uint8_t* pattern;
    const uint8_t* buffer;
};

bool Tester::run()
{
    int pos;

    BoyerMoore bm = BoyerMoore(pattern, pattern_len);

    if ( type == NOCASE )
    {
        pos = bm.search_nocase(buffer, buffer_len);
    }
    else
    {
        pos = bm.search(buffer, buffer_len);
    }

    return pos == index;
}

TEST_GROUP(boyer_moore_test_group) {};

TEST(boyer_moore_test_group, binary)
{
    const uint8_t pat[] = { 0xCA, 0xFE, 0xBA, 0xBE };

    const uint8_t buf[] = {
        0x00, 0x01, 0x02, 0x03,
        0x72, 0x01, 0x3F, 0x2B,
        0x1F, 0xCA, 0xFE, 0xBA,
        0xBE, 0x01, 0x02, 0x03,
    };

    BoyerMoore bm = BoyerMoore(pat, sizeof(pat));

    int pos = bm.search(buf, sizeof(buf));

    CHECK(pos == 9);
}

TEST(boyer_moore_test_group, empty)
{
    Tester t = Tester("abc", "", CASE, -1);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, start)
{
    Tester t = Tester("abc", "abc", CASE, 0);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, start_nocase)
{
    Tester t = Tester("abc", "aBc", NOCASE, 0);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, found1)
{
    Tester t = Tester("d", "abcdefg", CASE, 3);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, found2)
{
    Tester t = Tester("nan", "banana", CASE, 2);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, found3)
{
    Tester t = Tester("pan", "anpanman", CASE, 2);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, found4)
{
    Tester t = Tester("bcd", "abcd", CASE, 1);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, found5)
{
    Tester t = Tester("aa", "aaa", CASE, 0);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, found6)
{
    Tester t = Tester(
        "that", "which finally halts at tHaT point", NOCASE, 23);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, not_found1)
{
    Tester t = Tester("nnaaman", "anpanmanam", CASE, -1);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, not_found2)
{
    Tester t = Tester("abcd", "abc", CASE, -1);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, not_found3)
{
    Tester t = Tester("abcd", "bcd", CASE, -1);
    CHECK(t.run());
}

TEST(boyer_moore_test_group, not_found4)
{
    Tester t = Tester("baa", "aaaaa", CASE, -1);
    CHECK(t.run());
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

