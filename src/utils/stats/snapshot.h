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
#include <optional>
#include <string>
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
};

struct Group
{
    std::string name;
    std::vector<Counter> counters;
    std::vector<Table> tables;
};

struct Section
{
    std::string name;
    std::vector<Group> groups;
};

struct Snapshot
{
    std::vector<Section> sections;
};

struct RenderOptions
{
    bool include_zeros = false;    // we could give the user the option to include zero-value counters in the output
};

bool is_zero(const Counter& counter);
bool should_render(const Counter& counter, const RenderOptions& options);

} // namespace snort::stats

#endif
