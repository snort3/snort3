//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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
    size_t actual_hash_val;

    HashIp hash_hk;
    SfIp ip;

    ip.pton(AF_INET6, "aff:1200::b00:5600:0:0");
    actual_hash_val = hash_hk(ip);

#if defined(WORDS_BIGENDIAN)
    CHECK(actual_hash_val == (size_t)143908479889833984);
#else
    CHECK(actual_hash_val == (size_t)4521729);
#endif
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

