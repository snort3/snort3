//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stats.h"

#include <cassert>
#include <cmath>
#include <cstring>
#include <ostream>
#include <utility>

#include "control/control.h"
#include "detection/detection_engine.h"
#include "file_api/file_stats.h"
#include "filters/sfthreshold.h"
#include "framework/module.h"
#include "log/log_stats.h"
#include "log/messages.h"
#include "memory/memory_module.h"
#include "main/process.h"
#include "main/snort_config.h"
#include "memory/memory_cap.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/trough.h"
#include "profiler/profiler_impl.h"
#include "protocols/packet_manager.h"
#include "time/timersub.h"

#include "stats/output_json.h"
#include "stats/output_text.h"
#include "stats/response_buf.h"
#include "stats/snapshot.h"
#include "util.h"

#define USECS_PER_SEC 1000000.0

ProcessCount proc_stats;

namespace snort
{
THREAD_LOCAL PacketCount pc;
}

using namespace snort;

//-------------------------------------------------------------------------

static struct timeval starttime = {0, 0}, endtime = {0, 0}, currtime = {0, 0};

void TimeStart()
{
    gettimeofday(&starttime, nullptr);
}

void TimeStop()
{
    gettimeofday(&endtime, nullptr);
}

const struct timeval& get_time_start()
{
    return starttime;
}

const struct timeval& get_time_end()
{
    return endtime;
}

const struct timeval& get_time_curr()
{
    gettimeofday(&currtime, nullptr);
    return currtime;
}

static void timing_stats()
{
    struct timeval difftime;
    TIMERSUB(&endtime, &starttime, &difftime);

    uint32_t tmp = (uint32_t)difftime.tv_sec;

    uint32_t hrs  = tmp / SECONDS_PER_HOUR;
    tmp  = tmp % SECONDS_PER_HOUR;

    uint32_t mins = tmp / SECONDS_PER_MIN;
    uint32_t secs = tmp % SECONDS_PER_MIN;

    LogLabel("timing");

    LogMessage("%25.25s: %02d:%02d:%02d\n", "runtime", hrs, mins, secs);

    LogMessage("%25.25s: %lu.%06lu\n", "seconds",
        (unsigned long)difftime.tv_sec, (unsigned long)difftime.tv_usec);

    Module* daq = PluginManager::get_module("daq");
    assert(daq);

    uint64_t num_pkts = (uint64_t)daq->get_global_count("analyzed");
    uint64_t num_byts = (uint64_t)daq->get_global_count("rx_bytes");

    double total_secs = tmp + difftime.tv_usec / USECS_PER_SEC;

    if ( uint64_t pps = (uint64_t)llround(num_pkts / total_secs) )
        LogMessage("%25.25s: " STDu64 "\n", "pkts/sec", pps);

    if ( uint64_t mbps = (uint64_t)llround(8 * num_byts / total_secs / 1e6) )
        LogMessage("%25.25s: " STDu64 "\n", "Mbits/sec", mbps);
}

//-------------------------------------------------------------------------

const PegInfo pc_names[] =
{
    { CountType::NOW, "analyzed", "total packets processed" },
    { CountType::SUM, "hard_evals", "non-fast pattern rule evaluations" },
    { CountType::SUM, "raw_searches", "fast pattern searches in raw packet data" },
    { CountType::SUM, "cooked_searches", "fast pattern searches in cooked packet data" },
    { CountType::SUM, "pkt_searches", "fast pattern searches in packet data" },
    { CountType::SUM, "alt_searches", "alt fast pattern searches in packet data" },
    { CountType::SUM, "pdu_searches", "fast pattern searches in service buffers" },
    { CountType::SUM, "file_searches", "fast pattern searches in file buffer" },
    { CountType::SUM, "offloads", "fast pattern searches that were offloaded" },
    { CountType::SUM, "alerts", "alerts not including IP reputation" },
    { CountType::SUM, "total_alerts", "alerts including IP reputation" },
    { CountType::SUM, "logged", "logged packets" },
    { CountType::SUM, "passed", "passed packets" },
    { CountType::SUM, "match_limit", "fast pattern matches not processed" },
    { CountType::SUM, "queue_limit", "events not queued because queue full" },
    { CountType::SUM, "log_limit", "events queued but not logged" },
    { CountType::SUM, "event_limit", "events filtered" },
    { CountType::SUM, "alert_limit", "events previously triggered on same PDU" },
    { CountType::SUM, "context_stalls", "times processing stalled to wait for an available context" },
    { CountType::SUM, "offload_busy", "times offload was not available" },
    { CountType::SUM, "onload_waits", "times processing waited for onload to complete" },
    { CountType::SUM, "offload_fallback", "fast pattern offload search fallback attempts" },
    { CountType::SUM, "offload_failures", "fast pattern offload search failures" },
    { CountType::SUM, "offload_suspends", "fast pattern search suspends due to offload context chains" },
    { CountType::SUM, "cont_creations", "total number of continuations created" },
    { CountType::SUM, "cont_recalls", "total number of continuations recalled" },
    { CountType::SUM, "cont_flows", "total number of flows using continuation" },
    { CountType::SUM, "cont_evals", "total number of condition-met continuations" },
    { CountType::SUM, "cont_matches", "total number of continuations matched" },
    { CountType::SUM, "cont_mismatches", "total number of continuations mismatched" },
    { CountType::MAX, "cont_max_num", "peak number of simultaneous continuations per flow" },
    { CountType::SUM, "cont_match_distance", "total number of bytes jumped over by matched continuations"},
    { CountType::SUM, "cont_mismatch_distance", "total number of bytes jumped over by mismatched continuations"},
    { CountType::SUM, "buf_dumps", "total number of IPS buffers collected from matched rules" },
    { CountType::END, nullptr, nullptr }
};

const PegInfo proc_names[] =
{
    { CountType::SUM, "local_commands", "total local commands processed" },
    { CountType::SUM, "remote_commands", "total remote commands processed" },
    { CountType::SUM, "signals", "total signals processed" },
    { CountType::SUM, "conf_reloads", "number of times configuration was reloaded" },
    { CountType::SUM, "policy_reloads", "number of times policies were reloaded" },
    { CountType::SUM, "inspector_deletions", "number of times inspectors were deleted" },
    { CountType::SUM, "daq_reloads", "number of times daq configuration was reloaded" },
    { CountType::SUM, "attribute_table_reloads", "number of times hosts attribute table was reloaded" },
    { CountType::SUM, "attribute_table_hosts", "number of hosts added to the attribute table" },
    { CountType::SUM, "attribute_table_overflow", "number of host additions that failed due to attribute table full" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------

static bool module_less(const Module* lhs, const Module* rhs)
{
    return strcmp(lhs->get_name(), rhs->get_name()) < 0;
}

static bool module_is_skipped(const char* skip, const Module* mod)
{
    return skip && strstr(skip, mod->get_name());
}

static void add_peg_counters(stats::Group& group, const PegInfo* pegs,
    const std::vector<PegCount>& counts, int num_counts)
{
    if ( !pegs || num_counts <= 0 || (int)counts.size() < num_counts )
        return;

    group.counters.reserve(group.counters.size() + num_counts);
    for ( int i = 0; i < num_counts; ++i )
    {
        if ( pegs[i].type == CountType::END || !pegs[i].name )
            continue;

        stats::Counter counter;
        counter.set_name(pegs[i].name);
        counter.value = static_cast<uint64_t>(counts[i]);
        counter.type = pegs[i].type;
        group.counters.emplace_back(std::move(counter));
    }
}

static stats::Group collect_module_group(Module* mod)
{
    stats::Group group;

    if ( !mod || !mod->get_pegs() )
        return group;

    if ( mod->get_num_counts() < 0 )
        mod->init_stats();

    const int num_counts = mod->get_num_counts();
    if ( num_counts <= 0 )
        return group;

    group.name = mod->get_name();
    add_peg_counters(group, mod->get_pegs(), mod->get_dump_stats_results(), num_counts);
    return group;
}

static void add_packet_section(stats::Snapshot& snapshot, const PacketManager::Stats* packet_stats)
{
    stats::Section section;
    section.name = "Packet Statistics";
    section.groups.reserve(2);

    section.groups.emplace_back(collect_module_group(PluginManager::get_module("daq")));

    PacketManager::Stats stats{};
    if ( packet_stats )
        stats = *packet_stats;
    else
        PacketManager::get_global_stats(stats);

    std::vector<PacketManager::DisplayStat> display_stats;
    PacketManager::get_display_stats(stats, display_stats);

    stats::Group codec_group;
    codec_group.name = "codec";
    const PegCount total = display_stats.empty() ? 0 : display_stats[0].count;
    codec_group.counters.reserve(display_stats.size());
    for ( const auto& display_stat : display_stats )
    {
        stats::Counter counter;
        counter.set_name(display_stat.name);
        counter.value = static_cast<uint64_t>(display_stat.count);
        counter.total = total;
        counter.percent = total ? (100.0 * display_stat.count / total) :
            (100.0 * display_stat.count);
        codec_group.counters.emplace_back(std::move(counter));
    }
    section.groups.emplace_back(std::move(codec_group));

    snapshot.sections.emplace_back(std::move(section));
}

static void add_module_section(stats::Snapshot& snapshot)
{
    stats::Section section;
    section.name = "Module Statistics";
    const char* exclude = "daq snort memory";

    auto mods = PluginManager::get_all_modules();
    mods.sort(module_less);
    section.groups.reserve(mods.size());

    for ( auto* mod : mods )
    {
        if ( !mod || module_is_skipped(exclude, mod) || mod->stats_are_aggregated() )
            continue;

        if ( ModuleManager::is_dynamic_stats_module(mod) || mod->global_stats() )
        {
            std::lock_guard<std::mutex> lock(ModuleManager::stats_mutex);
            section.groups.emplace_back(collect_module_group(mod));
        }
        else
            section.groups.emplace_back(collect_module_group(mod));
    }

    snapshot.sections.emplace_back(std::move(section));
}

static void refresh_memory_stats()
{
    auto* memory_module = PluginManager::get_module("memory");
    if ( memory_module )
        static_cast<MemoryModule*>(memory_module)->refresh_process_heap_stats();
}

static void add_summary_section(stats::Snapshot& snapshot)
{
    stats::Section section;
    section.name = "Summary Statistics";
    section.groups.reserve(2);

    ProcessCount proc_snapshot;
    {
        std::lock_guard<std::mutex> lock(ModuleManager::stats_mutex);
        proc_snapshot = proc_stats;
    }

    stats::Group process_group;
    process_group.name = "process";
    std::vector<PegCount> process_counts(array_size(proc_names) - 1);
    const auto* process_values = reinterpret_cast<const PegCount*>(&proc_snapshot);
    for ( size_t i = 0; i < process_counts.size(); ++i )
        process_counts[i] = process_values[i];
    add_peg_counters(process_group, proc_names, process_counts, static_cast<int>(process_counts.size()));
    section.groups.emplace_back(std::move(process_group));

    refresh_memory_stats();
    section.groups.emplace_back(collect_module_group(PluginManager::get_module("memory")));

    snapshot.sections.emplace_back(std::move(section));
}

static stats::Snapshot collect_stats_snapshot(const PacketManager::Stats* packet_stats)
{
    stats::Snapshot snapshot;
    snapshot.sections.reserve(3);

    add_packet_section(snapshot, packet_stats);
    add_module_section(snapshot);

    // FIXIT-H: integrate dynamic stats into structured collection so JSON can render them.

    add_summary_section(snapshot);

    return snapshot;
}

static void render_text_snapshot(ControlConn* ctrlcon, const stats::Snapshot& snapshot)
{
    // FIXIT-H: remove this text-only hook after dynamic stats are collected in the shared model.
    stats::render_text(ctrlcon, snapshot, {}, [] {
        ModuleManager::dump_stats("daq snort memory", true);
    });
}

static void render_json_snapshot(ControlConn* ctrlcon, const stats::Snapshot& snapshot)
{
    StatsResponseBuf buffer(ctrlcon);
    std::ostream out(&buffer);
    stats::render_json(out, snapshot);
}

static void clear_dump_stats_state()
{
    auto mods = PluginManager::get_all_modules();

    for ( auto* mod : mods )
    {
        if ( mod )
            mod->clear_dump_stats_state();
    }
}

void DropStats(ControlConn* ctrlcon, bool already_accumulated,
    const PacketManager::Stats* packet_stats, StatsOutputFormat format)
{
    if ( !already_accumulated )
        ModuleManager::accumulate_dump_stats();

    auto snapshot = collect_stats_snapshot(packet_stats);

    if ( format == StatsOutputFormat::Json )
        render_json_snapshot(ctrlcon, snapshot);
    else
        render_text_snapshot(ctrlcon, snapshot);

    clear_dump_stats_state();
}

//-------------------------------------------------------------------------

// Here, we print out exit stats. They contain the usual stats dump, plus some
// extra timing stats. They always use text format for output.
void PrintStatistics()
{
    DropStats();
    timing_stats();

    // Print exit statistics under -q without changing logging in other threads.
    SnortConfig::ScopedLogQuietBypass quiet_bypass;
    Profiler::consolidate_stats();
    Profiler::show_stats();
}

//-------------------------------------------------------------------------

void sum_stats(
    PegCount* gpegs, PegCount* tpegs, unsigned n, bool dump_stats)
{
    for ( unsigned i = 0; i < n; ++i )
    {
        gpegs[i] += tpegs[i];
        if(!dump_stats)
            tpegs[i] = 0;
    }
}

static bool show_stat(
    bool head, PegCount count, const char* name, const char* module_name,
    FILE* fh = stdout)
{
    if ( !count )
        return head;

    if ( module_name && !head )
    {
        LogLabel(module_name, fh);
        head = true;
    }

    LogCount(name, count, fh);
    return head;
}

void show_stats(
    PegCount* pegs, const PegInfo* info, unsigned n, const char* module_name)
{
    bool head = false;

    for ( unsigned i = 0; i < n; ++i )
        head = show_stat(head, pegs[i], info[i].name, module_name);
}

void show_stats(
    PegCount* pegs, const PegInfo* info,
    const std::vector<unsigned>& peg_idxs, const char* module_name, FILE* fh)
{
    bool head = false;

    for ( const auto& i : peg_idxs)
        head = show_stat(head, pegs[i], info[i].name, module_name, fh);
}
