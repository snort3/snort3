//--------------------------------------------------------------------------
// Copyright (C) 2022-2026 Cisco and/or its affiliates. All rights reserved.
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

namespace snort
{
void WarningMessage(const char*, ...) { }
}

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

// Check that max_size smaller than entry_size is safely clamped to entry_size
TEST(lru_cache_local, max_size_less_than_entry_size)
{
    LruCacheLocalStats stats;
    // max_size < entry_size; constructor clamps to entry_size so the cache holds one entry
    LruCacheLocal<uint64_t, float, std::hash<uint64_t>> lru_cache(10, stats);

    bool is_new = false;

    for (int i = 0; i < 10; i++)
    {
        auto& entry = lru_cache.find_else_create(i, &is_new);
        entry = float(i) * 1.5f;
    }

    // only the most recently inserted entry should remain; earlier entries were pruned
    std::vector<std::pair<uint64_t, float>> vec;
    lru_cache.get_all_values(vec);
    CHECK(vec.size() == 1);          // cache holds exactly one entry
    CHECK(lru_cache.count(9) == 1);  // last inserted key (9) is present
    CHECK(lru_cache.count(5) == 0);  // earlier key (1,2,..5...8) was evicted by prune
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
