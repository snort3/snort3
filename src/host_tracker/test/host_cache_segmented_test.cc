//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// host_cache_segmented_test.cc author Raza Shafiq <rshafiq@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>

#include "host_tracker/host_cache.h"
#include "host_tracker/host_cache_segmented.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "sfip/sf_ip.h"

using namespace std;
using namespace snort;

namespace snort
{
char* snort_strdup(const char* s)
{ return strdup(s); }
time_t packet_time() { return 0; }
void FatalError(const char* fmt, ...) { (void)fmt; exit(1); }

}

TEST_GROUP(host_cache_segmented)
{
};

TEST(host_cache_segmented, get_segments_test)
{
    HostCacheSegmentedIp hc(4,4000);
    hc.init();
    CHECK(hc.get_segments() == 4);
    CHECK(hc.get_memcap_per_segment() == 4000);
    CHECK(hc.get_max_size() == 16000);
    hc.term();
}


TEST(host_cache_segmented, cache_setup)
{
    HostCacheSegmentedIp hc;
    hc.setup(2,2000);
    hc.init();
    CHECK(hc.get_segments() == 2);
    CHECK(hc.get_memcap_per_segment() == 1000);
    CHECK(hc.get_max_size() == 2000);
    hc.term();
}

TEST(host_cache_segmented, one_segment)
{
    HostCacheSegmentedIp hc3(1,4000);
    hc3.init();
    CHECK(hc3.get_segments() == 1);
    CHECK(hc3.get_memcap_per_segment() == 4000);
    CHECK(hc3.get_max_size() == 4000);
    hc3.term();
}

TEST(host_cache_segmented, set_max_size_test)
{
    HostCacheSegmentedIp hc4(16,1000);
    hc4.init();
    CHECK(hc4.get_segments() == 16);
    CHECK(hc4.get_memcap_per_segment() == 1000);
    hc4.set_max_size(40000);
    CHECK(hc4.get_segments() == 16);
    CHECK(hc4.get_memcap_per_segment() == 2500);
    CHECK(hc4.get_max_size() == 40000);
    hc4.term();
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
