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

#ifndef STATS_SNAPSHOT_H
#define STATS_SNAPSHOT_H

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "framework/counts.h"

namespace snort::stats
{

using Value = std::variant<std::monostate, bool, int64_t, uint64_t, double, std::string>;

struct Counter
{
    void set_name(const char* name)
    {
        borrowed_name = name;
        owned_name.clear();
    }

    void set_name(const std::string& name)
    {
        borrowed_name = nullptr;
        owned_name = name;
    }

    const char* get_name() const
    { return borrowed_name ? borrowed_name : owned_name.c_str(); }

    const char* borrowed_name = nullptr;
    std::string owned_name;
    Value value;
    std::optional<CountType> type;
    std::optional<PegCount> total;
    std::optional<double> percent;
};

struct Table
{
    std::string name;
    std::vector<std::string> columns;
    std::vector<std::vector<Value>> rows;
    bool first_column_has_colon = false;
};

struct Group
{
    std::string name;
    std::vector<Counter> counters;
    std::deque<Table> tables;
};

struct Section
{
    std::string name;
    std::deque<Group> groups;
};

struct Snapshot
{
    std::deque<Section> sections;
};

struct DynamicStatsPolicy
{
    bool include_zeros = false;
};

class Builder
{
public:
    explicit Builder(Snapshot& snapshot) : snapshot(snapshot) { }

    Section& section(const char* name)
    {
        auto& section = snapshot.sections.emplace_back();
        section.name = name ? name : "";
        return section;
    }

    static Group& group(Section& parent_section, const char* name)
    {
        auto& stats_group = parent_section.groups.emplace_back();
        stats_group.name = name ? name : "";
        return stats_group;
    }

    static Table& table(Group& parent_group, const char* name, std::vector<std::string> columns,
        bool first_column_has_colon = false)
    {
        auto& stats_table = parent_group.tables.emplace_back();
        stats_table.name = name ? name : "";
        stats_table.columns = std::move(columns);
        stats_table.first_column_has_colon = first_column_has_colon;
        return stats_table;
    }

    static void row(Table& stats_table, std::vector<Value> values)
    { stats_table.rows.emplace_back(std::move(values)); }

    static void counter(Group& parent_group, const char* name, Value value)
    {
        const std::string counter_name = name ? name : "";
        counter(parent_group, counter_name, std::move(value));
    }

    static void counter(Group& parent_group, const std::string& name, Value value)
    {
        Counter counter;
        counter.set_name(name);
        counter.value = std::move(value);
        parent_group.counters.emplace_back(std::move(counter));
    }

private:
    Snapshot& snapshot;
};

} // namespace snort::stats

#endif
