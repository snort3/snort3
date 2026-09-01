//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include "file_api/file_capture.h"
#include "file_api/file_cache.h"
#include "file_api/file_service.h"
#include "utils/stats/snapshot.h"

static bool name_file_type = false;
static bool name_zero_file_type = false;
static bool use_file_cache = false;
static uint64_t file_cache_entries = 0;

std::string file_type_name(uint32_t id)
{
    if (name_file_type && id == 1)
        return "TEST";

    if (name_zero_file_type && id == 2)
        return "ZERO";

    return "";
}

namespace snort
{
bool FileService::file_signature_enabled = false;
FileCache* FileService::file_cache = nullptr;

int64_t FileCapture::get_buffers_max()
{ return 0; }

int64_t FileCapture::get_buffers_in_use()
{ return 0; }

void FileCapture::collect_mem_usage(stats::Builder&, stats::Group&) { }

void FileService::collect_cache_usage(stats::Builder& builder, stats::Group& group)
{
    if (use_file_cache)
        builder.counter(group, "File cache entries", file_cache_entries);
}
}

// cppcheck-suppress functionStatic
int64_t FileCache::get_num_entries()
{ return 0; }

#include "../file_stats.cc"

static void reset_file_stats()
{
    name_file_type = false;
    name_zero_file_type = false;
    use_file_cache = false;
    file_cache_entries = 0;
    file_stats_clear();
}

TEST_CASE("file stats collection skips totals when no rows are renderable", "[file_stats]")
{
    reset_file_stats();
    file_totals.files_processed[1][0] = 1;

    snort::stats::Snapshot snapshot;
    snort::stats::Builder builder(snapshot);
    snort::stats::DynamicStatsPolicy policy;

    file_stats_collect(builder, policy);

    CHECK(snapshot.sections.empty());
}

TEST_CASE("file stats collection includes cache usage without file rows", "[file_stats]")
{
    reset_file_stats();
    use_file_cache = true;
    file_cache_entries = 1;

    snort::stats::Snapshot snapshot;
    snort::stats::Builder builder(snapshot);
    snort::stats::DynamicStatsPolicy policy;

    file_stats_collect(builder, policy);

    REQUIRE(snapshot.sections.size() == 1);
    const auto& section = snapshot.sections[0];
    CHECK(section.name == "File Statistics");
    REQUIRE(section.groups.size() == 1);
    const auto& group = section.groups[0];
    CHECK(group.name == "file stats");
    CHECK(group.tables.empty());
    REQUIRE(group.counters.size() == 1);
    CHECK(std::string(group.counters[0].get_name()) == "File cache entries");
    CHECK(std::get<uint64_t>(group.counters[0].value) == 1);
}

TEST_CASE("file stats collection includes valid rows and cache usage without zero policy", "[file_stats]")
{
    reset_file_stats();
    name_file_type = true;
    name_zero_file_type = true;
    use_file_cache = true;
    file_cache_entries = 1;
    file_totals.files_processed[1][0] = 2;
    file_totals.files_processed[1][1] = 3;
    file_totals.data_processed[1][0] = 20;
    file_totals.data_processed[1][1] = 30;

    snort::stats::Snapshot snapshot;
    snort::stats::Builder builder(snapshot);
    snort::stats::DynamicStatsPolicy policy;

    file_stats_collect(builder, policy);

    REQUIRE(snapshot.sections.size() == 1);
    const auto& section = snapshot.sections[0];
    CHECK(section.name == "File Statistics");
    REQUIRE(section.groups.size() == 1);
    const auto& group = section.groups[0];
    REQUIRE(group.tables.size() == 1);
    REQUIRE(group.counters.size() == 1);
    CHECK(std::string(group.counters[0].get_name()) == "File cache entries");
    CHECK(std::get<uint64_t>(group.counters[0].value) == 1);

    const auto& rows = group.tables[0].rows;
    REQUIRE(rows.size() == 2);
    for ( const auto& row : rows )
        CHECK(std::get<std::string>(row[0]) != "ZERO(2)");

    REQUIRE(rows[0].size() == 5);
    CHECK(std::get<std::string>(rows[0][0]) == "TEST(1)");
    CHECK(std::get<uint64_t>(rows[0][1]) == 2);
    CHECK(std::get<uint64_t>(rows[0][2]) == 3);
    CHECK(std::get<uint64_t>(rows[0][3]) == 20);
    CHECK(std::get<uint64_t>(rows[0][4]) == 30);

    REQUIRE(rows[1].size() == 5);
    CHECK(std::get<std::string>(rows[1][0]) == "Total");
    CHECK(std::get<uint64_t>(rows[1][1]) == 2);
    CHECK(std::get<uint64_t>(rows[1][2]) == 3);
    CHECK(std::get<uint64_t>(rows[1][3]) == 20);
    CHECK(std::get<uint64_t>(rows[1][4]) == 30);
}

TEST_CASE("file stats collection can include zero rows by policy", "[file_stats]")
{
    reset_file_stats();
    name_file_type = true;

    snort::stats::Snapshot snapshot;
    snort::stats::Builder builder(snapshot);
    snort::stats::DynamicStatsPolicy policy;
    policy.include_zeros = true;

    file_stats_collect(builder, policy);

    REQUIRE(snapshot.sections.size() == 1);
    const auto& section = snapshot.sections[0];
    CHECK(section.name == "File Statistics");
    REQUIRE(section.groups.size() == 1);
    REQUIRE(section.groups[0].tables.size() == 1);

    const auto& rows = section.groups[0].tables[0].rows;
    REQUIRE(rows.size() == 2);
    REQUIRE(rows[0].size() == 5);
    CHECK(std::get<std::string>(rows[0][0]) == "TEST(1)");
    CHECK(std::get<uint64_t>(rows[0][1]) == 0);
    CHECK(std::get<uint64_t>(rows[0][2]) == 0);
    CHECK(std::get<uint64_t>(rows[0][3]) == 0);
    CHECK(std::get<uint64_t>(rows[0][4]) == 0);

    REQUIRE(rows[1].size() == 5);
    CHECK(std::get<std::string>(rows[1][0]) == "Total");
    CHECK(std::get<uint64_t>(rows[1][1]) == 0);
    CHECK(std::get<uint64_t>(rows[1][2]) == 0);
    CHECK(std::get<uint64_t>(rows[1][3]) == 0);
    CHECK(std::get<uint64_t>(rows[1][4]) == 0);
}
