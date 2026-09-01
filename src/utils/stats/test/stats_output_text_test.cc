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

#include "../output_text.cc"

static unsigned log_text_calls = 0;
static unsigned log_count_calls = 0;
static unsigned log_stat_calls = 0;
static std::string log_text_message;
static std::string log_count_name;
static uint64_t log_count_value = 0;

static void reset_log_output()
{
    log_text_calls = 0;
    log_count_calls = 0;
    log_stat_calls = 0;
    log_text_message.clear();
    log_count_name.clear();
    log_count_value = 0;
}

namespace snort
{
uint32_t SnortConfig::logging_flags = 0;

void set_log_conn(ControlConn*) { }
void LogLabel(const char*, FILE*) { }
void LogText(const char* message, FILE*)
{
    ++log_text_calls;
    log_text_message = message ? message : "";
}
void LogCount(const char* name, uint64_t value, FILE*)
{
    ++log_count_calls;
    log_count_name = name ? name : "";
    log_count_value = value;
}
void LogStat(const char*, uint64_t, uint64_t, FILE*) { ++log_stat_calls; }
}

namespace memory
{
void MemoryCap::print(bool, bool) { }
}

static Counter make_counter(const Value& value)
{
    Counter counter;
    counter.value = value;
    return counter;
}

TEST_CASE("text stats counter values convert to unsigned values", "[stats_output_text]")
{
    CHECK(counter_value_as_u64(make_counter(std::monostate{})) == 0);
    CHECK(counter_value_as_u64(make_counter(false)) == 0);
    CHECK(counter_value_as_u64(make_counter(true)) == 0);
    CHECK(counter_value_as_u64(make_counter(static_cast<int64_t>(-1))) == 0);
    CHECK(counter_value_as_u64(make_counter(static_cast<int64_t>(0))) == 0);
    CHECK(counter_value_as_u64(make_counter(static_cast<int64_t>(42))) == 42);
    CHECK(counter_value_as_u64(make_counter(static_cast<uint64_t>(0))) == 0);
    CHECK(counter_value_as_u64(make_counter(static_cast<uint64_t>(42))) == 42);
    CHECK(counter_value_as_u64(make_counter(0.0)) == 0);
    CHECK(counter_value_as_u64(make_counter(-1.25)) == 0);
    CHECK(counter_value_as_u64(make_counter(42.75)) == 42);
    CHECK(counter_value_as_u64(make_counter(std::string("42"))) == 0);
}

TEST_CASE("text stats values render as text", "[stats_output_text]")
{
    CHECK(value_as_text(std::monostate{}) == "");
    CHECK(value_as_text(false) == "false");
    CHECK(value_as_text(true) == "true");
    CHECK(value_as_text(static_cast<int64_t>(-42)) == "-42");
    CHECK(value_as_text(static_cast<int64_t>(42)) == "42");
    CHECK(value_as_text(static_cast<uint64_t>(42)) == "42");
    CHECK(value_as_text(1.25) == "1.250");
    CHECK(value_as_text(0.0) == "0.000");
    CHECK(value_as_text(std::string()) == "");
    CHECK(value_as_text(std::string("active")) == "active");
}

TEST_CASE("text stats percentages handle zero totals", "[stats_output_text]")
{
    CHECK(calc_pct(0, 0) == 0.0);
    CHECK(calc_pct(1, 0) == 0.0);
    CHECK(calc_pct(1, 4) == 25.0);
}

TEST_CASE("text stats output skips empty tables in renderable groups", "[stats_output_text]")
{
    reset_log_output();

    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Module Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "appid";

    auto& table = group.tables.emplace_back();
    table.name = "empty";
    table.columns = { "name" };

    Counter counter;
    counter.set_name("packets");
    counter.value = static_cast<uint64_t>(1);
    group.counters.emplace_back(counter);

    render_text(nullptr, snapshot, RenderOptions{});

    CHECK(log_text_calls == 0);
    CHECK(log_count_calls == 1);
    CHECK(log_count_name == "packets");
    CHECK(log_count_value == 1);
}

TEST_CASE("text stats output renders zero count counters when requested", "[stats_output_text]")
{
    reset_log_output();

    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Module Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "appid";

    Counter counter;
    counter.set_name("packets");
    counter.value = static_cast<uint64_t>(0);
    group.counters.emplace_back(counter);

    RenderOptions options;
    options.include_zeros = true;
    render_text(nullptr, snapshot, options);

    CHECK(log_count_calls == 0);
    CHECK(log_stat_calls == 0);
    CHECK(log_text_calls == 1);
    CHECK(log_text_message == "                  packets: 0");
}

TEST_CASE("text stats output renders zero percentage counters when requested", "[stats_output_text]")
{
    reset_log_output();

    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Module Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "appid";

    Counter counter;
    counter.set_name("packets");
    counter.value = static_cast<uint64_t>(0);
    counter.total = 10;
    group.counters.emplace_back(counter);

    RenderOptions options;
    options.include_zeros = true;
    render_text(nullptr, snapshot, options);

    CHECK(log_count_calls == 0);
    CHECK(log_stat_calls == 0);
    CHECK(log_text_calls == 1);
    CHECK(log_text_message == "                  packets: 0           \t(  0.000%)");
}
