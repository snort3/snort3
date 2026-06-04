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

#include <sstream>

#include "catch/catch.hpp"

#include "../output_json.h"
#include "../snapshot.h"

using namespace snort::stats;

static Counter make_counter(const char* name, const Value& value)
{
    Counter counter;
    counter.set_name(name);
    counter.value = value;
    return counter;
}

// cppcheck-suppress syntaxError
TEST_CASE("json stats output renders an empty snapshot", "[stats_output_json]")
{
    Snapshot snapshot;

    std::ostringstream out;
    render_json(out, snapshot);

    const char* expected = R"({ "sections": [  ] })"
        "\n";
    CHECK(out.str() == expected);
}

TEST_CASE("json stats output skips groups without renderable content", "[stats_output_json]")
{
    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Packet Statistics";

    auto& empty_group = section.groups.emplace_back();
    empty_group.name = "empty";

    auto& zero_group = section.groups.emplace_back();
    zero_group.name = "zero";

    Counter zero;
    zero.set_name("packets");
    zero.value = static_cast<uint64_t>(0);
    zero_group.counters.emplace_back(zero);

    auto& empty_table_group = section.groups.emplace_back();
    empty_table_group.name = "empty_table";

    auto& table = empty_table_group.tables.emplace_back();
    table.name = "flows";
    table.columns.emplace_back("flow");

    std::ostringstream out;
    render_json(out, snapshot);

    const char* expected =
        R"({ "sections": [ { "name": "Packet Statistics", "groups": [  ] } ] })"
        "\n";
    CHECK(out.str() == expected);
}

TEST_CASE("json stats output filters each zero value type", "[stats_output_json]")
{
    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Packet Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "values";

    group.counters.emplace_back(make_counter("unset", std::monostate{}));
    group.counters.emplace_back(make_counter("false", false));
    group.counters.emplace_back(make_counter("true", true));
    group.counters.emplace_back(make_counter("signed_zero", static_cast<int64_t>(0)));
    group.counters.emplace_back(make_counter("signed", static_cast<int64_t>(-5)));
    group.counters.emplace_back(make_counter("unsigned_zero", static_cast<uint64_t>(0)));
    group.counters.emplace_back(make_counter("unsigned", static_cast<uint64_t>(7)));
    group.counters.emplace_back(make_counter("double_zero", 0.0));
    group.counters.emplace_back(make_counter("double", 1.25));
    group.counters.emplace_back(make_counter("empty_string", std::string()));
    group.counters.emplace_back(make_counter("string", std::string("active")));

    std::ostringstream out;
    render_json(out, snapshot);

    const char* expected =
        R"({ "sections": [ { "name": "Packet Statistics", "groups": [ { "name": "values", "counters": [ )"
        R"({ "name": "true", "value": true }, )"
        R"({ "name": "signed", "value": -5 }, )"
        R"({ "name": "unsigned", "value": 7 }, )"
        R"({ "name": "double", "value": 1.250 }, )"
        R"({ "name": "string", "value": "active" } ] } ] } ] })"
        "\n";
    CHECK(out.str() == expected);
}

TEST_CASE("json stats output filters zeros and trims metadata", "[stats_output_json]")
{
    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Packet Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "codec";

    Counter zero;
    zero.set_name("total");
    zero.value = static_cast<uint64_t>(0);
    zero.type = CountType::SUM;
    group.counters.emplace_back(zero);

    Counter now;
    now.set_name("current");
    now.value = static_cast<uint64_t>(7);
    now.type = CountType::NOW;
    group.counters.emplace_back(now);

    Counter max;
    max.set_name("peak");
    max.value = static_cast<uint64_t>(9);
    max.type = CountType::MAX;
    group.counters.emplace_back(max);

    Counter percent;
    percent.set_name("tcp\"name");
    percent.value = static_cast<uint64_t>(3);
    percent.total = 10;
    percent.percent = 30.0;
    group.counters.emplace_back(percent);

    std::ostringstream out;
    render_json(out, snapshot);

    const char* expected =
        R"({ "sections": [ { "name": "Packet Statistics", "groups": [ { "name": "codec", "counters": [ )"
        R"({ "name": "current", "value": 7 }, )"
        R"({ "name": "peak", "value": 9 }, )"
        R"({ "name": "tcp\"name", "value": 3, "percent": 30.000 } ] } ] } ] })"
        "\n";
    CHECK(out.str() == expected);
}

TEST_CASE("json stats output renders tables with mixed value types", "[stats_output_json]")
{
    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Module Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "appid";

    auto& table = group.tables.emplace_back();
    table.name = "flows";
    table.columns = { "name", "enabled", "delta", "rate", "state" };
    table.rows.emplace_back(std::vector<Value>{
        std::string("tcp\"name"),
        true,
        static_cast<int64_t>(-2),
        1.25,
        std::monostate{}
    });
    table.rows.emplace_back(std::vector<Value>{
        std::string("udp\\name"),
        false,
        static_cast<uint64_t>(42),
        0.5,
        std::string("done")
    });

    std::ostringstream out;
    render_json(out, snapshot);

    const char* expected =
        R"({ "sections": [ { "name": "Module Statistics", "groups": [ { "name": "appid", )"
        R"("counters": [  ], "tables": [ { "name": "flows", "columns": [ )"
        R"("name", "enabled", "delta", "rate", "state" ], "rows": [ )"
        R"([ "tcp\"name", true, -2, 1.250, null ], )"
        R"([ "udp\\name", false, 42, 0.500, "done" ] ] } ] } ] } ] })"
        "\n";
    CHECK(out.str() == expected);
}

TEST_CASE("json stats output preserves rendered empty strings", "[stats_output_json]")
{
    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Module Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "appid";

    group.counters.emplace_back(make_counter("empty_string", std::string()));

    auto& table = group.tables.emplace_back();
    table.name = "flows";
    table.columns = { "name", "state", "note" };
    table.rows.emplace_back(std::vector<Value>{
        std::string("tcp"),
        std::string(),
        std::string("done")
    });

    RenderOptions options;
    options.include_zeros = true;

    std::ostringstream out;
    render_json(out, snapshot, options);

    const char* expected =
        R"({ "sections": [ { "name": "Module Statistics", "groups": [ { "name": "appid", "counters": [ )"
        R"({ "name": "empty_string", "value": "" } ], "tables": [ { "name": "flows", "columns": [ )"
        R"("name", "state", "note" ], "rows": [ [ "tcp", "", "done" ] ] } ] } ] } ] })"
        "\n";
    CHECK(out.str() == expected);
}

TEST_CASE("json stats output can include zeros by policy", "[stats_output_json]")
{
    Snapshot snapshot;
    auto& section = snapshot.sections.emplace_back();
    section.name = "Module Statistics";

    auto& group = section.groups.emplace_back();
    group.name = "appid";

    Counter counter;
    counter.set_name("packets");
    counter.value = static_cast<uint64_t>(0);
    counter.type = CountType::SUM;
    group.counters.emplace_back(counter);

    RenderOptions options;
    options.include_zeros = true;

    std::ostringstream out;
    render_json(out, snapshot, options);

    const char* expected =
        R"({ "sections": [ { "name": "Module Statistics", "groups": [ { "name": "appid", "counters": [ )"
        R"({ "name": "packets", "value": 0 } ] } ] } ] })"
        "\n";
    CHECK(out.str() == expected);
}
