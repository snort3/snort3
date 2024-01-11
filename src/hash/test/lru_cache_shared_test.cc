//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

//  Test LruCacheShared find and get_all_data functions.
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

// Test set / get max size.
TEST(lru_cache_shared, max_size)
{
    std::string data;
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    size_t sz = lru_cache.get_max_size();
    CHECK(sz == 5);

    for (size_t i = 0; i < sz; i++)
        lru_cache[i]->assign(std::to_string(i));

    // Check that we can't set max size to 0
    CHECK(lru_cache.set_max_size(0) == false);
    CHECK(lru_cache.get_max_size() == sz);

    // this prunes and should kick out the three oldest, i.e. 0, 1 and 2
    CHECK(lru_cache.set_max_size(2) == true);

    auto vec = lru_cache.get_all_data();
    CHECK(vec.size() == 2);
    CHECK(vec[0].first == 4 and *vec[0].second == "4");
    CHECK(vec[1].first == 3 and *vec[1].second == "3");
}

//  Test the remove functions.
TEST(lru_cache_shared, remove_test)
{
    std::string data;
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(5);

    for (int i = 0; i < 5; i++)
    {
        lru_cache[i]->assign(std::to_string(i));
        CHECK(true == lru_cache.remove(i));
        CHECK(lru_cache.find(i) == nullptr);
    }

    CHECK(0 == lru_cache.size());

    //  Test remove API that returns the removed data.
    std::shared_ptr<std::string> data_ptr;
    lru_cache[1]->assign("one");
    CHECK(1 == lru_cache.size());
    CHECK(true == lru_cache.remove(1, data_ptr));
    CHECK(*data_ptr == "one");
    CHECK(0 == lru_cache.size());

    lru_cache[1]->assign("one");
    lru_cache[2]->assign("two");
    CHECK(2 == lru_cache.size());

    //  Verify that removing an item that does not exist does not affect
    //  cache.
    CHECK(false == lru_cache.remove(3));
    CHECK(false == lru_cache.remove(4, data_ptr));
    CHECK(2 == lru_cache.size());

    auto vec = lru_cache.get_all_data();
    CHECK(2 == vec.size());
    CHECK(vec[0].first == 2 and *vec[0].second == "two");
    CHECK(vec[1].first == 1 and *vec[1].second == "one");
}

TEST(lru_cache_shared, find_else_insert)
{
    std::shared_ptr<std::string> data(new std::string("12345"));
    std::shared_ptr<std::string> data2(new std::string("54321"));
    LruCacheShared<int, std::string, std::hash<int> > lru_cache(2);
    LcsInsertStatus status;

    CHECK(false == lru_cache.find_else_insert(1,data));
    CHECK(1 == lru_cache.size());

    CHECK(true == lru_cache.find_else_insert(1,data));
    CHECK(1 == lru_cache.size());

    CHECK(data == lru_cache.find_else_insert(1,data,&status));
    CHECK(status == LcsInsertStatus::LCS_ITEM_PRESENT);
    CHECK(1 == lru_cache.size());

    CHECK(data2 == lru_cache.find_else_insert(2,data2,&status));
    CHECK(status == LcsInsertStatus::LCS_ITEM_INSERTED);
    CHECK(2 == lru_cache.size());

    CHECK(data2 == lru_cache.find_else_insert(1,data2,&status, true));
    CHECK(status == LcsInsertStatus::LCS_ITEM_REPLACED);
    CHECK(*(lru_cache.find(1)) == "54321");
    CHECK(2 == lru_cache.size());
}

//  Test statistics counters.
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

    lru_cache.remove(7);    // Removes - hit
    lru_cache.remove(10);   // Removes - miss

    const PegCount* stats = lru_cache.get_counts();

    CHECK(stats[0] == 10);  //  adds
    CHECK(stats[1] == 7);   //  alloc prunes
    CHECK(stats[2] == 0);   //  bytes in use
    CHECK(stats[3] == 0);   //  items in use
    CHECK(stats[4] == 3);   //  find hits
    CHECK(stats[5] == 12);  //  find misses
    CHECK(stats[6] == 0);   //  reload prunes
    CHECK(stats[7] == 1);   //  removes

    // Check statistics names.
    const PegInfo* pegs = lru_cache.get_pegs();
    CHECK(!strcmp(pegs[0].name, "adds"));
    CHECK(!strcmp(pegs[1].name, "alloc_prunes"));
    CHECK(!strcmp(pegs[2].name, "bytes_in_use"));
    CHECK(!strcmp(pegs[3].name, "items_in_use"));
    CHECK(!strcmp(pegs[4].name, "find_hits"));
    CHECK(!strcmp(pegs[5].name, "find_misses"));
    CHECK(!strcmp(pegs[6].name, "reload_prunes"));
    CHECK(!strcmp(pegs[7].name, "removes"));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
