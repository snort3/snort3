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

// host_cache_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for HostTracker class

#include "host_tracker/host_cache.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(host_cache)
{
};

//  Test HostIpKey
TEST(host_cache, host_ip_key_test)
{
    HostIpKey zeroed_hk;
    uint8_t expected_hk[16] = { 0xde,0xad,0xbe,0xef,0xab,0xcd,0xef,0x01,0x23,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };

    memset(zeroed_hk.ip_addr, 0, sizeof(zeroed_hk.ip_addr));

    HostIpKey hkey1;
    CHECK(hkey1 == zeroed_hk);

    HostIpKey hkey2(expected_hk);
    CHECK(hkey2 == expected_hk);
}

//  Test HashHostIpKey
TEST(host_cache, hash_test)
{
    size_t expected_hash_val = 4521729;
    size_t actual_hash_val;
    uint8_t hk[16] = { 0x0a,0xff,0x12,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0x56,0x00,0x00,0x00,0x00,0x00 };

    HashHostIpKey hash_hk;

    actual_hash_val = hash_hk(hk);
    CHECK(actual_hash_val == expected_hash_val);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

