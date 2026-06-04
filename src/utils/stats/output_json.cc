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

#include "output_json.h"

#include "helpers/json_stream.h"

using namespace snort;
using namespace snort::stats;

static void put_value(JsonStream& json, const char* key, const Value& value)
{
    if ( std::get_if<std::monostate>(&value) )
        json.put(key);
    else if ( const auto* v = std::get_if<bool>(&value) )
    {
        if ( *v )
            json.put_true(key);
        else
            json.put_false(key);
    }
    else if ( const auto* v = std::get_if<int64_t>(&value) )
        json.put(key, *v);
    else if ( const auto* v = std::get_if<uint64_t>(&value) )
        json.uput(key, *v);
    else if ( const auto* v = std::get_if<double>(&value) )
        json.put(key, *v, 3);
    else if ( const auto* v = std::get_if<std::string>(&value) )
        json.put_string(key, *v);
    else
        json.put(key);
}

static bool has_renderable_rows(const Table& table, const RenderOptions&)
{
    return !table.rows.empty();
}

static bool has_renderable_counters(const Group& group, const RenderOptions& options)
{
    for ( const auto& counter : group.counters )
    {
        if ( should_render(counter, options) )
            return true;
    }

    for ( const auto& table : group.tables )
    {
        if ( has_renderable_rows(table, options) )
            return true;
    }

    return false;
}

static void render_counter(JsonStream& json, const Counter& counter)
{
    json.open();
    json.put("name", counter.get_name());
    put_value(json, "value", counter.value);

    if ( counter.percent )
        json.put("percent", *counter.percent, 3);

    json.close();
}

static void render_table(JsonStream& json, const Table& table)
{
    json.open();
    json.put("name", table.name);

    json.open_array("columns");
    for ( const auto& column : table.columns )
        json.put(nullptr, column);
    json.close_array();

    json.open_array("rows");
    for ( const auto& row : table.rows )
    {
        json.open_array();
        for ( const auto& cell : row )
            put_value(json, nullptr, cell);
        json.close_array();
    }
    json.close_array();

    json.close();
}

static void render_group(JsonStream& json, const Group& group, const RenderOptions& options)
{
    json.open();
    json.put("name", group.name);

    json.open_array("counters");
    for ( const auto& counter : group.counters )
    {
        if ( should_render(counter, options) )
            render_counter(json, counter);
    }
    json.close_array();

    if ( !group.tables.empty() )
    {
        json.open_array("tables");
        for ( const auto& table : group.tables )
        {
            if ( has_renderable_rows(table, options) )
                render_table(json, table);
        }
        json.close_array();
    }

    json.close();
}

static void render_section(JsonStream& json, const Section& section, const RenderOptions& options)
{
    json.open();
    json.put("name", section.name);

    json.open_array("groups");
    for ( const auto& group : section.groups )
    {
        if ( has_renderable_counters(group, options) )
            render_group(json, group, options);
    }
    json.close_array();

    json.close();
}

void snort::stats::render_json(std::ostream& out, const Snapshot& snapshot, const RenderOptions& options)
{
    JsonStream json(out);

    json.open();
    json.open_array("sections");
    for ( const auto& section : snapshot.sections )
        render_section(json, section, options);
    json.close_array();
    json.close();
}
