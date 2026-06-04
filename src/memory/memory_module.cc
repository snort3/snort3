//--------------------------------------------------------------------------
// Copyright (C) 2016-2026 Cisco and/or its affiliates. All rights reserved.
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

// memory_module.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "memory_module.h"

#include "main/snort_config.h"
#include "trace/trace.h"

#include "memory_cap.h"
#include "memory_config.h"

using namespace snort;

THREAD_LOCAL const Trace* memory_trace = nullptr;

// -----------------------------------------------------------------------------
// memory attributes
// -----------------------------------------------------------------------------

#define s_name "memory"
#define s_help \
    "memory management configuration"

static const Parameter s_params[] =
{
    { "cap", Parameter::PT_INT, "0:maxSZ", "0",
        "set the process cap on memory in bytes (0 to disable)" },

    { "interval", Parameter::PT_INT, "0:max32", "50",
        "approximate ms between memory epochs (0 to disable)" },

    { "prune_target", Parameter::PT_INT, "1:max32", "1048576",
        "bytes to prune per packet thread prune cycle" },

    { "threshold", Parameter::PT_INT, "1:100", "100",
        "scale cap to account for heap overhead" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

namespace memory
{
constexpr int start_up_use_peg_idx = 0;
constexpr int cur_in_use_peg_idx = 1;
constexpr int max_in_use_peg_idx = 2;
constexpr int epochs_peg_idx = 3;
constexpr int app_all_peg_idx = 12;
constexpr int active_peg_idx = 13;
constexpr int resident_peg_idx = 14;
constexpr int retained_peg_idx = 15;

static bool is_process_heap_peg(int idx)
{
    switch ( idx )
    {
    case start_up_use_peg_idx:
    case cur_in_use_peg_idx:
    case max_in_use_peg_idx:
    case epochs_peg_idx:
    case app_all_peg_idx:
    case active_peg_idx:
    case resident_peg_idx:
    case retained_peg_idx:
        return true;
    default:
        return false;
    }
}
}

const PegInfo mem_pegs[] =
{
    { CountType::NOW, "start_up_use", "memory used before packet processing" },
    { CountType::NOW, "cur_in_use", "current memory used" },
    { CountType::MAX, "max_in_use", "maximum memory used" },
    { CountType::SUM, "epochs", "number of memory updates" },
    { CountType::NOW, "allocated", "total amount of memory allocated by packet threads" },
    { CountType::NOW, "deallocated", "total amount of memory deallocated by packet threads" },
    { CountType::SUM, "reap_cycles", "number of actionable over-limit conditions" },
    { CountType::SUM, "reap_attempts", "attempts to reclaim memory" },
    { CountType::SUM, "reap_failures", "failures to reclaim memory" },
    { CountType::SUM, "reap_aborts", "abort pruning before target due to process under limit" },
    { CountType::SUM, "reap_decrease", "total amount of the decrease in thread memory while process over limit" },
    { CountType::SUM, "reap_increase", "total amount of the increase in thread memory while process over limit" },
    { CountType::NOW, "app_all", "total bytes allocated by application" },
    { CountType::NOW, "active", "total bytes allocated in active pages" },
    { CountType::NOW, "resident", "maximum bytes physically resident" },
    { CountType::NOW, "retained", "total bytes not returned to OS" },

    { CountType::END, nullptr, nullptr }
};

// -----------------------------------------------------------------------------
// memory module
// -----------------------------------------------------------------------------

MemoryModule::MemoryModule() :
    Module(s_name, s_help, s_params)
{ }

bool MemoryModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("cap") )
        sc->memory->cap = v.get_size();

    else if ( v.is("interval") )
        sc->memory->interval = v.get_uint32();

    else if ( v.is("prune_target") )
        sc->memory->prune_target = v.get_uint32();

    else if ( v.is("threshold") )
        sc->memory->threshold = v.get_uint8();

    return true;
}

bool MemoryModule::end(const char*, int, SnortConfig* sc)
{
    sc->memory->enabled = true;
    return true;
}

const PegInfo* MemoryModule::get_pegs() const
{ return mem_pegs; }

PegCount* MemoryModule::get_counts() const
{ return (PegCount*)&memory::MemoryCap::get_mem_stats(); }

void MemoryModule::prep_counts(bool dump_stats)
{
    if ( get_instance_id() != 0 )
        return;

    memory::MemoryCap::update_global_stats(dump_stats);
}

void MemoryModule::refresh_process_heap_stats()
{
    // Refresh process-wide heap pegs in dump_stats_results before rendering.
    // These values may have changed since accumulate() ran (e.g. the shutdown
    // epoch bumped by stop()). Per-thread pegs (reap_*, allocated, deallocated)
    // were correctly aggregated from all packet threads and are left unchanged.
    prep_counts(true);
    const PegCount* fresh = get_counts();
    int n = get_num_counts();

    if ( n > 0 and (int)dump_stats_results.size() >= n )
    {
        for ( int i = 0; i < n; i++ )
        {
            if ( memory::is_process_heap_peg(i) )
                dump_stats_results[i] = fresh[i];
        }
    }
}

void MemoryModule::show_stats()
{
    refresh_process_heap_stats();
    Module::show_stats();
}

void MemoryModule::reset_stats()
{
    // reset_thread_stats() only acts when called from the owning packet thread;
    // it is a no-op on the main thread. Per-thread live counters (thread_mem_stats)
    // are reset by each thread on its own tinit/reset cycle.
    memory::MemoryCap::reset_thread_stats();
    Module::reset_stats();
}

void MemoryModule::set_trace(const Trace* trace) const
{ memory_trace = trace; }

const TraceOption* MemoryModule::get_trace_options() const
{
    static const TraceOption memory_trace_options(nullptr, 0, nullptr);

    return &memory_trace_options;
}
