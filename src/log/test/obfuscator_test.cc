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

// obfuscator_test.cc author Victor Roemer <viroemer@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "../obfuscator.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

TEST_GROUP(ObfuscatorTests)
{ };

TEST(ObfuscatorTests, Test_1_Block)
{
    char buf[70];
    memset(buf, 'A', sizeof(buf)-1);
    buf[ sizeof(buf)-1 ] = '\0';

    Obfuscator ob;

    ob.push(0, sizeof(buf)-1);

    ObfuscatorBlock b;
    for ( bool more = ob.first(b); more; more = ob.next(b) )
        memset(&buf[ b.offset ], '.', b.length);

    char buf2[sizeof(buf)];
    memset(buf2, '.', sizeof(buf2)-1);
    buf2[ sizeof(buf2)-1 ] = '\0';

    CHECK_TRUE(memcmp(buf, buf2, sizeof(buf)) == 0);
}

TEST(ObfuscatorTests, Test_2_Block)
{
    char buf[70];
    memset(buf, 'A', sizeof(buf)-1);
    buf[ sizeof(buf)-1 ] = '\0';

    Obfuscator ob;

    ob.push(0, 10);
    ob.push(10, sizeof(buf)-10-1);

    ObfuscatorBlock b;
    for ( bool more = ob.first(b); more; more = ob.next(b) )
        memset(&buf[ b.offset ], '.', b.length);

    char buf2[sizeof(buf)];
    memset(buf2, '.', sizeof(buf2)-1);
    buf2[ sizeof(buf2)-1 ] = '\0';

    CHECK_TRUE(memcmp(buf, buf2, sizeof(buf)) == 0);
}

TEST(ObfuscatorTests, Test_3_Block)
{
    char buf[70];
    memset(buf, 'A', sizeof(buf)-1);
    buf[ sizeof(buf)-1 ] = '\0';

    Obfuscator ob;

    ob.push(0, 10);
    ob.push(10, 10);
    ob.push(20, sizeof(buf)-20-1);

    ObfuscatorBlock b;
    for ( bool more = ob.first(b); more; more = ob.next(b) )
        memset(&buf[ b.offset ], '.', b.length);

    char buf2[sizeof(buf)];
    memset(buf2, '.', sizeof(buf2)-1);
    buf2[ sizeof(buf2)-1 ] = '\0';

    CHECK_TRUE(memcmp(buf, buf2, sizeof(buf)) == 0);
}

TEST(ObfuscatorTests, Test_3_Block_with_Gaps)
{
    char buf[70];
    memset(buf, 'A', sizeof(buf)-1);
    buf[ sizeof(buf)-1 ] = '\0';

    Obfuscator ob;

    ob.push(0, 10);                // 0-9 '..........'
    ob.push(20, 10);               // 10-19 'AAAAAAAAAA' 20-29 '..........'
    ob.push(40, sizeof(buf)-40-1); // 30-39 'AAAAAAAAAA' 40-68 '.............................' 69 '\0'

    ObfuscatorBlock b;
    for ( bool more = ob.first(b); more; more = ob.next(b) )
        memset(&buf[ b.offset ], '.', b.length);

    const char buf2[70] = "..........AAAAAAAAAA..........AAAAAAAAAA.............................";
    CHECK_TRUE(memcmp(buf, buf2, sizeof(buf)) == 0);
}

TEST(ObfuscatorTests, EmptyListTest)
{
    Obfuscator ob;
    ObfuscatorBlock b;
    CHECK_FALSE(ob.first(b));
}

TEST(ObfuscatorTests, EmptyList2Test)
{
    Obfuscator ob;
    ObfuscatorBlock b;
    CHECK_FALSE(ob.next(b));
}

TEST(ObfuscatorTests, EmptyList3Test)
{
    Obfuscator ob;
    ob.push(0, 69);

    ObfuscatorBlock b;
    CHECK_TRUE(ob.first(b) );
    CHECK_FALSE(ob.next(b) );
    CHECK_FALSE(ob.next(b) );
}

TEST(ObfuscatorTests, NoExactMatch)
{
    Obfuscator ob;
    ob.push(0, 1);
    ob.push(0, 1);
    ob.push(0, 1);
    ob.push(0, 1);
    ob.push(0, 1);
    ob.push(0, 1);
    ob.push(0, 1);
    ob.push(0, 1);

    auto b = ob.begin();
    CHECK_TRUE(++b == ob.end());
}

TEST(ObfuscatorTests, UpdateExactMatch)
{
    Obfuscator ob;
    ob.push(0, 1);
    ob.push(0, 2);
    ob.push(0, 3);
    ob.push(0, 4);
    ob.push(0, 5);
    ob.push(0, 6);
    ob.push(0, 7);
    ob.push(0, 8);

    auto b = ob.begin();
    CHECK_TRUE(++b == ob.end());
}

//
// Verify ObfuscatorBlock's are sorted on access
//
TEST(ObfuscatorTests, SortedElements)
{
    Obfuscator ob;
    ob.push(50,0);
    ob.push(100,0);
    ob.push(0,0);

    uint32_t last = 0;
    for ( auto &b: ob )
    {
        CHECK_TRUE(last <= b.offset);
        last = b.offset;
    }
}

TEST(ObfuscatorTests, Overlaps)
{
    Obfuscator ob;
    ob.push(50,49);
    ob.push(100,1);
    ob.push(0,100);

    uint32_t last = 0;
    for ( auto &b: ob )
    {
        CHECK_TRUE(last <= b.offset);
        last = b.offset;
    }
}

int main(int argc, char* argv[])
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

