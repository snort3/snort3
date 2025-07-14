//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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

// lru_cache_local.h author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/lru_cache_local.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(lru_cache_local)
{
};

TEST(lru_cache_local, basic)
{
    LruCacheLocalStats stats;
    LruCacheLocal<int, int, std::hash<int>> lru_cache(40, stats);

    // Check pruning in LRU order; memcap = 40 bytes would hold 2 entries
    int key = 1;
    int val = 100;
    lru_cache.add(key, val);

    key = 2;
    val = 200;
    lru_cache.add(key, val);

    key = 3;
    val = 300;
    lru_cache.add(key, val);

    // Check entries are stored in LRU order indeed
    std::vector<std::pair<int, int>> vec;
    lru_cache.get_all_values(vec);
    CHECK(vec.size() == 2);
    CHECK(vec[0].first == 3 and vec[0].second == 300);
    CHECK(vec[1].first == 2 and vec[1].second == 200);

    bool is_new = false;

    // Check non-existent entry; find_else_create() would return a new entry
    auto& entry = lru_cache.find_else_create(4, &is_new);
    CHECK_EQUAL(true, is_new);
    entry = 400;

    // Subsequent calls would return the same one
    CHECK(lru_cache.find_else_create(4, &is_new) == 400);
    CHECK_EQUAL(false, is_new);
    entry = 4000;

    is_new = true;
    CHECK(lru_cache.find_else_create(4, &is_new) == 4000);
    CHECK_EQUAL(false, is_new);

    // The cache is changed after the above calls
    vec.clear();
    lru_cache.get_all_values(vec);
    CHECK(vec.size() == 2);
    CHECK(vec[0].first == 4 and vec[0].second == 4000);
    CHECK(vec[1].first == 3 and vec[1].second == 300);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
