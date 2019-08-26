//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

// host_cache_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for the host cache APIs

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker/host_cache.h"

#include <cstring>

#include "main/snort_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

namespace snort
{
char* snort_strdup(const char* str)
{
    return strdup(str);
}
time_t packet_time() { return 0; }
}

TEST_GROUP(host_cache)
{
};

//  Test HashIp
TEST(host_cache, hash_test)
{
    size_t expected_hash_val = 4521729;
    size_t actual_hash_val;
    uint8_t hk[16] =
    { 0x0a,0xff,0x12,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0x56,0x00,0x00,0x00,0x00,0x00 };

    HashIp hash_hk;
    SfIp ip;

    ip.set(hk);
    actual_hash_val = hash_hk(ip);
    CHECK(actual_hash_val == expected_hash_val);
}

int main(int argc, char** argv)
{
    //  Use this if you want to turn off memory checks entirely:
    // MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();

    return CommandLineTestRunner::RunAllTests(argc, argv);
}

