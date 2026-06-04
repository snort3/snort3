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

#include "control/control.h"
#include "log/log_stats.h"
#include "main/snort_config.h"
#include "memory/memory_cap.h"

using namespace snort;
using namespace snort::stats;

namespace
{
enum TextSectionIndex
{
    PACKET_SECTION,
    MODULE_SECTION,
    SUMMARY_SECTION
};
}

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

static void render_group(const Group& group, const RenderOptions& options)
{
    bool wrote_label = false;

    for ( const auto& counter : group.counters )
    {
        if ( !should_render(counter, options) )
            continue;

        if ( !wrote_label )
        {
            LogLabel(group.name.c_str());
            wrote_label = true;
        }

        const uint64_t value = counter_value_as_u64(counter);
        if ( counter.total )
            LogStat(counter.get_name(), value, *counter.total);
        else
            LogCount(counter.get_name(), value);
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
    const RenderOptions& options,
    const DynamicStatsRenderer& render_dynamic_stats)
{
    set_log_conn(ctrlcon);

    if ( snapshot.sections.size() > PACKET_SECTION )
        render_section(snapshot.sections[PACKET_SECTION], options);

    if ( snapshot.sections.size() > MODULE_SECTION )
    {
        render_section(snapshot.sections[MODULE_SECTION], options);

        if ( render_dynamic_stats )
            render_dynamic_stats();
    }

    if ( snapshot.sections.size() > SUMMARY_SECTION )
    {
        render_section(snapshot.sections[SUMMARY_SECTION], options);
        memory::MemoryCap::print(SnortConfig::log_verbose());
    }

    set_log_conn(nullptr);
}
