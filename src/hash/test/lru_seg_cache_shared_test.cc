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
// lru_seg_cache_shared_test.cc author Raza Shafiq <rshafiq@cisco.com>

#include "hash/lru_segmented_cache_shared.h"
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(segmented_lru_cache)
{
};

// Test SegmentedLruCache constructor and member access.
TEST(segmented_lru_cache, constructor_test)
{
    SegmentedLruCache<int, std::string> lru_cache(8);

    CHECK(lru_cache.get_max_size() == 8);
    CHECK(lru_cache.size() == 0);
}

// Test SegmentedLruCache insert and find functions.
TEST(segmented_lru_cache, insert_test)
{
    SegmentedLruCache<int, std::string> lru_cache(4);

    auto data = lru_cache[0];
    CHECK(data == lru_cache.find(0));
    data->assign("zero");

    data = lru_cache[1];
    CHECK(data == lru_cache.find(1));
    data->assign("one");

    data = lru_cache[2];
    CHECK(data == lru_cache.find(2));
    data->assign("two");

    data = lru_cache[0];
    data->assign("new_zero");

    CHECK(nullptr == lru_cache.find(3));

    data = lru_cache[3];
    CHECK(data == lru_cache.find(3));
    data->assign("three");

    const auto&& vec = lru_cache.get_all_data();
    CHECK(vec.size() == 4);
}

// Test mem_size function
TEST(segmented_lru_cache, mem_size_test)
{
    SegmentedLruCache<int, std::string> cache(5);
    std::shared_ptr<std::string> data(new std::string("hello"));
    cache.find_else_insert(1, data);

    // Assuming each segment's metadata takes some space, hence checking for non-zero size
    CHECK(0 != cache.mem_size());
}

// Test get_counts function
TEST(segmented_lru_cache, get_counts_test)
{
    SegmentedLruCache<int, std::string> cache(5);
    // Assuming get_counts function returns a non-null pointer
    CHECK(nullptr != cache.get_counts());
}

// Test size function
TEST(segmented_lru_cache, size_test)
{
    SegmentedLruCache<int, std::string> cache(5);
    std::shared_ptr<std::string> data(new std::string("hello"));
    cache.find_else_insert(1, data);

    CHECK(1 == cache.size());
}

// Test set/get max size.
TEST(segmented_lru_cache, max_size)
{
    SegmentedLruCache<int, std::string> lru_cache(16);

    size_t sz = lru_cache.get_max_size();
    CHECK(sz == 16);

    CHECK(lru_cache.set_max_size(8) == true);
    CHECK(lru_cache.get_max_size() == 8);
}

// Test the remove functions.
TEST(segmented_lru_cache, remove_test)
{
    SegmentedLruCache<int, std::string> lru_cache(4);

    for ( int i = 0; i < 4; i++ )
    {
        std::shared_ptr<std::string> data(new std::string(std::to_string(i)));
        CHECK(false == lru_cache.find_else_insert(i, data));
        CHECK(true == lru_cache.find_else_insert(i, data));
        CHECK(true == lru_cache.remove(i));
        CHECK(lru_cache.find(i) == nullptr);
    }

    CHECK(0 == lru_cache.size());

    std::shared_ptr<std::string> data_ptr;
    std::shared_ptr<std::string> data(new std::string("one"));
    lru_cache.find_else_insert(1,data);
    CHECK(1 == lru_cache.size());
    CHECK(true == lru_cache.remove(1, data_ptr));
    CHECK(*data_ptr == "one");
    CHECK(0 == lru_cache.size());
}

// Test the find_else_insert function.
TEST(segmented_lru_cache, find_else_insert)
{
    std::shared_ptr<std::string> data(new std::string("12345"));
    SegmentedLruCache<int, std::string> lru_cache(8);

    CHECK(false == lru_cache.find_else_insert(1, data));
    CHECK(1 == lru_cache.size());

    CHECK(true == lru_cache.find_else_insert(1, data));
    CHECK(1 == lru_cache.size());
}

// Test 8 segments
TEST (segmented_lru_cache, segements_8)
{
    SegmentedLruCache<int, std::string> lru_cache(1024,8);
    std::shared_ptr<std::string> data(new std::string("12345"));

    CHECK(false == lru_cache.find_else_insert(1, data));
    CHECK(1 == lru_cache.size());

    CHECK(true == lru_cache.find_else_insert(1, data));
    CHECK(1 == lru_cache.size());

    CHECK (8 == lru_cache.get_segment_count());

}

// Test statistics counters.
TEST(segmented_lru_cache, stats_test)
{
    SegmentedLruCache<int, std::string> lru_cache(8);

    for (int i = 0; i < 10; i++)
        lru_cache[i];

    lru_cache.find(7);
    lru_cache.find(8);
    lru_cache.find(9);
    lru_cache.find(10);
    lru_cache.find(11);

    CHECK(lru_cache.set_max_size(16) == true);

    lru_cache.remove(7);
    lru_cache.remove(8);
    lru_cache.remove(11); // not in cache

    const PegCount* stats = lru_cache.get_counts();

    CHECK(stats[0] == 10);  // adds
    CHECK(stats[1] == 2);   // alloc_prunes
    CHECK(stats[2] == 0);   // bytes_in_use
    CHECK(stats[3] == 0);   // items_in_use
    CHECK(stats[4] == 3);   // find_hits
    CHECK(stats[5] == 12);   // find_misses
    CHECK(stats[6] == 0);   // reload_prunes
    CHECK(stats[7] == 2);   // removes
    CHECK(stats[8] == 0);   // replaced

}

// Test the find_else_insert method for item replacement
TEST(segmented_lru_cache, find_else_insert_replace)
{
    SegmentedLruCache<int, std::string> lru_cache(8);
    std::shared_ptr<std::string> data(new std::string("hello"));
    LcsInsertStatus status;

    lru_cache.find_else_insert(1, data, &status, false);  // initial insert
    CHECK(status == LcsInsertStatus::LCS_ITEM_INSERTED);  // Check status for initial insert

    std::shared_ptr<std::string> newData(new std::string("world"));
    std::shared_ptr<std::string> returnedData = lru_cache.find_else_insert(1, newData, &status, true);  // replace existing item
    CHECK(returnedData != nullptr);
    CHECK(status == LcsInsertStatus::LCS_ITEM_REPLACED);  // Check status for item replacement
    CHECK(*returnedData == "world");  // Check data for item replacement

    returnedData = lru_cache.find_else_insert(1, newData, &status, false);  // attempt insert without replace flag
    CHECK(returnedData != nullptr);
    CHECK(status == LcsInsertStatus::LCS_ITEM_PRESENT);  // Check status for existing item
    CHECK(*returnedData == "world");  // Data should remain unchanged
}



int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
