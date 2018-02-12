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

//  Test LruCacheShared constructor and member access.
TEST(lru_cache_shared, constructor_test)
{
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    CHECK(lru_cache.get_max_size() == 5);
    CHECK(lru_cache.size() == 0);
}

//  Test LruCacheShared insert, find and get_all_data functions.
TEST(lru_cache_shared, insert_test)
{
    std::string data;
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    lru_cache.insert(0, "zero");
    CHECK(true == lru_cache.find(0, data));
    CHECK("zero" == data);

    lru_cache.insert(1, "one");
    CHECK(true == lru_cache.find(1, data));
    CHECK("one" == data);

    lru_cache.insert(2, "two");
    CHECK(true == lru_cache.find(2, data));
    CHECK("two" == data);

    //  Verify find fails for non-existent item.
    CHECK(false == lru_cache.find(3, data));

    //  Verify that insert will replace data if key exists already.
    lru_cache.insert(1, "new one");
    CHECK(true == lru_cache.find(1, data));
    CHECK("new one" == data);

    //  Verify current number of entries in cache.
    CHECK(3 == lru_cache.size());

    //  Verify that the data is in LRU order.
    auto vec = lru_cache.get_all_data();
    CHECK(3 == vec.size());
    CHECK((vec[0] == std::make_pair(1, std::string("new one"))));
    CHECK((vec[1] == std::make_pair(2, std::string("two"))));
    CHECK((vec[2] == std::make_pair(0, std::string("zero"))));
}

//  Test that the least recently used items are removed when we exceed
//  the capacity of the LruCache.
TEST(lru_cache_shared, lru_removal_test)
{
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    for (int i = 0; i < 10; i++)
    {
        lru_cache.insert(i, std::to_string(i));
    }

    CHECK(5 == lru_cache.size());

    //  Verify that the data is in LRU order and is correct.
    auto vec = lru_cache.get_all_data();
    CHECK(5 == vec.size());
    CHECK((vec[0] == std::make_pair(9, std::string("9"))));
    CHECK((vec[1] == std::make_pair(8, std::string("8"))));
    CHECK((vec[2] == std::make_pair(7, std::string("7"))));
    CHECK((vec[3] == std::make_pair(6, std::string("6"))));
    CHECK((vec[4] == std::make_pair(5, std::string("5"))));
}

//  Test the remove and clear functions.
TEST(lru_cache_shared, remove_test)
{
    std::string data;
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    for (int i = 0; i < 5; i++)
    {
        lru_cache.insert(i, std::to_string(i));
        CHECK(true == lru_cache.find(i, data));
        CHECK(data == std::to_string(i));

        CHECK(true == lru_cache.remove(i));
        CHECK(false == lru_cache.find(i, data));
    }

    CHECK(0 == lru_cache.size());

    //  Test remove API that returns the removed data.
    lru_cache.insert(1, "one");
    CHECK(1 == lru_cache.size());
    CHECK(true == lru_cache.remove(1, data));
    CHECK(data == "one");
    CHECK(0 == lru_cache.size());

    lru_cache.insert(1, "one");
    lru_cache.insert(2, "two");
    CHECK(2 == lru_cache.size());

    //  Verify that removing an item that does not exist does not affect
    //  cache.
    CHECK(false == lru_cache.remove(3));
    CHECK(false == lru_cache.remove(4, data));
    CHECK(2 == lru_cache.size());

    auto vec = lru_cache.get_all_data();
    CHECK(2 == vec.size());
    CHECK((vec[0] == std::make_pair(2, std::string("two"))));
    CHECK((vec[1] == std::make_pair(1, std::string("one"))));

    //  Verify that clear() removes all entries.
    lru_cache.clear();
    CHECK(0 == lru_cache.size());

    vec = lru_cache.get_all_data();
    CHECK(vec.empty());
}

//  Test statistics counters.
TEST(lru_cache_shared, stats_test)
{
    std::string data;
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    for (int i = 0; i < 10; i++)
    {
        lru_cache.insert(i, std::to_string(i));
    }

    lru_cache.insert(8, "new-eight");  //  Replace entries.
    lru_cache.insert(9, "new-nine");

    CHECK(5 == lru_cache.size());

    lru_cache.find(7, data);     //  Hits
    lru_cache.find(8, data);
    lru_cache.find(9, data);

    lru_cache.remove(7);
    lru_cache.remove(8);
    lru_cache.remove(9, data);
    CHECK("new-nine" == data);

    lru_cache.find(8, data);    //  Misses now that they're removed.
    lru_cache.find(9, data);

    lru_cache.remove(100);  //  Removing a non-existent entry does not
                            //  increase remove count.

    lru_cache.clear();

    PegCount* stats = lru_cache.get_counts();

    CHECK(stats[0] == 10);  //  adds
    CHECK(stats[1] == 2);   //  replaces
    CHECK(stats[2] == 5);   //  prunes
    CHECK(stats[3] == 3);   //  find hits
    CHECK(stats[4] == 2);   //  find misses
    CHECK(stats[5] == 3);   //  removes
    CHECK(stats[6] == 1);   //  clears

    // Check statistics names.
    const PegInfo* pegs = lru_cache.get_pegs();
    CHECK(!strcmp(pegs[0].name, "lru_cache_adds"));
    CHECK(!strcmp(pegs[1].name, "lru_cache_replaces"));
    CHECK(!strcmp(pegs[2].name, "lru_cache_prunes"));
    CHECK(!strcmp(pegs[3].name, "lru_cache_find_hits"));
    CHECK(!strcmp(pegs[4].name, "lru_cache_find_misses"));
    CHECK(!strcmp(pegs[5].name, "lru_cache_removes"));
    CHECK(!strcmp(pegs[6].name, "lru_cache_clears"));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

