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

#include "output_text.h"

#include <iomanip>
#include <sstream>

#include "control/control.h"
#include "log/log_stats.h"
#include "main/snort_config.h"
#include "memory/memory_cap.h"

using namespace snort;
using namespace snort::stats;

static constexpr const char* SUMMARY_STATS_SECTION = "Summary Statistics";

// Text output column width; other renderers can choose their own layout.
static constexpr size_t FIRST_COLUMN_WIDTH = 25;
static constexpr size_t COUNTER_VALUE_WIDTH = 12;
static constexpr size_t PERCENT_VALUE_WIDTH = 7;
static constexpr unsigned PERCENT_PRECISION = 3;

static uint64_t counter_value_as_u64(const Counter& counter)
{
    if ( const auto* value = std::get_if<uint64_t>(&counter.value) )
        return *value;

    if ( const auto* value = std::get_if<int64_t>(&counter.value) )
        return *value > 0 ? static_cast<uint64_t>(*value) : 0;

    if ( const auto* value = std::get_if<double>(&counter.value) )
        return *value > 0 ? static_cast<uint64_t>(*value) : 0;

    return 0;
}

static std::string value_as_text(const Value& value)
{
    if ( const auto* v = std::get_if<bool>(&value) )
        return *v ? "true" : "false";

    if ( const auto* v = std::get_if<int64_t>(&value) )
        return std::to_string(*v);

    if ( const auto* v = std::get_if<uint64_t>(&value) )
        return std::to_string(*v);

    if ( const auto* v = std::get_if<double>(&value) )
    {
        std::ostringstream text;
        text << std::fixed << std::setprecision(3) << *v;
        return text.str();
    }

    if ( const auto* v = std::get_if<std::string>(&value) )
        return *v;

    return {};
}

static std::string first_column_text(const Value& value)
{
    std::string text = value_as_text(value);
    if ( text.size() > FIRST_COLUMN_WIDTH )
        text.resize(FIRST_COLUMN_WIDTH);
    return text;
}

static void append_table_line(std::ostringstream& line, const std::vector<Value>& values,
    bool first_column_has_colon)
{
    const auto flags = line.flags();

    const std::string first = values.empty() ? std::string() : first_column_text(values[0]);
    line << std::setw(FIRST_COLUMN_WIDTH) << std::right << first
        << (first_column_has_colon ? ": " : " ");

    for ( size_t i = 1; i < values.size(); ++i )
    {
        if ( i > 1 )
            line << ' ';

        line << std::setw(10) << std::left << value_as_text(values[i]);
    }

    line.flags(flags);
}

static bool has_renderable_rows(const Table& table)
{
    return !table.rows.empty();
}

static bool has_renderable_content(const Group& group, const RenderOptions& options)
{
    for ( const auto& table : group.tables )
    {
        if ( has_renderable_rows(table) )
            return true;
    }

    for ( const auto& counter : group.counters )
    {
        if ( should_render(counter, options) )
            return true;
    }

    return false;
}

static void render_table(const Table& table)
{
    if ( !has_renderable_rows(table) )
        return;

    std::ostringstream line;
    std::vector<Value> header;
    header.reserve(table.columns.size());
    for ( const auto& column : table.columns )
        header.emplace_back(column);
    append_table_line(line, header, table.first_column_has_colon);
    LogText(line.str().c_str());

    for ( const auto& row : table.rows )
    {
        line.str(std::string());
        line.clear();
        append_table_line(line, row, table.first_column_has_colon);
        LogText(line.str().c_str());
    }
}

static std::string counter_name_as_text(const Counter& counter)
{
    std::string text = counter.get_name();
    if ( text.size() > FIRST_COLUMN_WIDTH )
        text.resize(FIRST_COLUMN_WIDTH);
    return text;
}

static double calc_pct(uint64_t count, uint64_t total)
{
    if ( total == 0 )
        return 0.0;

    return static_cast<double>(count) / static_cast<double>(total) * 100.0;
}

static void render_zero_counter(const Counter& counter, uint64_t value)
{
    std::ostringstream line;
    line << std::setw(FIRST_COLUMN_WIDTH) << std::right << counter_name_as_text(counter) << ": ";

    if ( counter.total )
    {
        line << std::setw(COUNTER_VALUE_WIDTH) << std::left << value << "\t("
            << std::setw(PERCENT_VALUE_WIDTH) << std::right << std::fixed
            << std::setprecision(PERCENT_PRECISION)
            << calc_pct(value, *counter.total) << "%)";
    }
    else
        line << value;

    LogText(line.str().c_str());
}

static void render_counter(const Counter& counter, const RenderOptions& options)
{
    const uint64_t value = counter_value_as_u64(counter);

    if ( value || !options.include_zeros )
    {
        if ( counter.total )
            LogStat(counter.get_name(), value, *counter.total);
        else
            LogCount(counter.get_name(), value);

        return;
    }

    render_zero_counter(counter, value);
}

static void render_group(const Group& group, const RenderOptions& options)
{
    if ( !has_renderable_content(group, options) )
        return;

    LogLabel(group.name.c_str());

    for ( const auto& table : group.tables )
        render_table(table);

    for ( const auto& counter : group.counters )
    {
        if ( !should_render(counter, options) )
            continue;

        render_counter(counter, options);
    }
}

static void render_section(const Section& section, const RenderOptions& options)
{
    LogLabel(section.name.c_str());

    for ( const auto& group : section.groups )
        render_group(group, options);
}

void snort::stats::render_text(
    ControlConn* ctrlcon,
    const Snapshot& snapshot,
    const RenderOptions& options)
{
    set_log_conn(ctrlcon);

    for ( const auto& section : snapshot.sections )
    {
        render_section(section, options);

        if ( section.name == SUMMARY_STATS_SECTION )
            memory::MemoryCap::print(SnortConfig::log_verbose());
    }

    set_log_conn(nullptr);
}
