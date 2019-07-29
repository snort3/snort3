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

// lru_cache_shared_test.cc author Steve Chew <stechew@cisco.com>
// unit tests for LruCacheShared class

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/lru_cache_shared.h"

#include <cstring>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(lru_cache_shared)
{
};

//  Test LruCacheShared find, operator[], and get_all_data functions.
TEST(lru_cache_shared, insert_test)
{
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(3);

    auto data = lru_cache[0];
    CHECK(data == lru_cache.find(0));
    data->assign("zero");

    data = lru_cache[1];
    CHECK(data == lru_cache.find(1));
    data->assign("one");

    data = lru_cache[2];
    CHECK(data == lru_cache.find(2));
    data->assign("two");

    // Replace existing
    data = lru_cache[0];
    data->assign("new_zero");

    //  Verify find fails for non-existent item.
    CHECK(nullptr == lru_cache.find(3));

    // Replace least recently used when capacity exceeds
    data = lru_cache[3];
    CHECK(data == lru_cache.find(3));
    data->assign("three");

    //  Verify current number of entries in cache and LRU order.
    const auto&& vec = lru_cache.get_all_data();
    CHECK(vec.size() == 3);
    CHECK(vec[0].second->compare("three") == 0);
    CHECK(vec[1].second->compare("new_zero") == 0);
    CHECK(vec[2].second->compare("two") == 0);
}

//  Test statistics counters and set_max_size.
TEST(lru_cache_shared, stats_test)
{
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    for (int i = 0; i < 10; i++)
        lru_cache[i];

    lru_cache.find(7);     //  Hits
    lru_cache.find(8);
    lru_cache.find(9);

    lru_cache.find(10);    //  Misses; in addition to previous 10
    lru_cache.find(11);

    CHECK(lru_cache.set_max_size(3) == true); // change size prunes; in addition to previous 5

    PegCount* stats = lru_cache.get_counts();

    CHECK(stats[0] == 10);  //  adds
    CHECK(stats[1] == 7);   //  prunes
    CHECK(stats[2] == 3);   //  find hits
    CHECK(stats[3] == 12);  //  find misses

    // Check statistics names.
    const PegInfo* pegs = lru_cache.get_pegs();
    CHECK(!strcmp(pegs[0].name, "lru_cache_adds"));
    CHECK(!strcmp(pegs[1].name, "lru_cache_prunes"));
    CHECK(!strcmp(pegs[2].name, "lru_cache_find_hits"));
    CHECK(!strcmp(pegs[3].name, "lru_cache_find_misses"));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

