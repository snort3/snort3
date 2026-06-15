
//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

// tp_appid_module_api.cc author Lukasz Czarnik <lczarnik@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tp_appid_module_api.h"

#include "managers/module_manager.h"
#include "profiler/profiler.h"

#include "appid_module.h"
#include "tp_lib_handler.h"


static void* tp_appid_profiler_malloc(size_t size)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    return operator new(size);
}

static void tp_appid_profiler_free(void* p)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    if (p)
        operator delete(p);
}

static constexpr size_t ALLOCATION_TRACKER_HEADER_SIZE = alignof(std::max_align_t);

static void* tp_appid_profiler_malloc_with_stats(size_t size)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    auto ptr = operator new(size+ALLOCATION_TRACKER_HEADER_SIZE);
    *(uint32_t*)ptr = size;
    appid_stats.tp_mem_bytes_in_use += size;
    appid_stats.tp_mem_allocations++;
    return static_cast<uint8_t*>(ptr) + ALLOCATION_TRACKER_HEADER_SIZE;
}

static void tp_appid_profiler_free_with_stats(void* p)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    if (p)
    {
        auto ptr = static_cast<uint8_t*>(p) - ALLOCATION_TRACKER_HEADER_SIZE;
        uint32_t size = *(uint32_t*)ptr;
        appid_stats.tp_mem_bytes_in_use -= size;
        appid_stats.tp_mem_frees++;
        operator delete(ptr);
    }
}

static TPAppidProfilerFunctions tp_appid_profiler_functions = {tp_appid_profiler_malloc, tp_appid_profiler_free};
static TPAppidProfilerFunctions tp_appid_profiler_stats_functions = {tp_appid_profiler_malloc_with_stats, tp_appid_profiler_free_with_stats};

TPAppidProfilerFunctions get_tp_appid_profiler_functions(bool is_profiling_enabled)
{
    return is_profiling_enabled ? tp_appid_profiler_stats_functions : tp_appid_profiler_functions;
}
