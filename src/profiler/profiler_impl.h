//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// profiler_impl.h author Joel Cornett <jocornet@cisco.com>

#ifndef PROFILER_IMPL_H
#define PROFILER_IMPL_H

#include "profiler_defs.h"

namespace snort
{
class Module;
struct ProfileStats;
}

class ProfilerNodeMap;

class Profiler
{
public:
    static void register_module(snort::Module*);
    static void register_module(const char*, const char*, snort::Module*);

    static void start();
    static void stop(uint64_t);

    static void consolidate_stats(snort::ProfilerType = snort::PROFILER_TYPE_BOTH);

    static void reset_stats(snort::ProfilerType = snort::PROFILER_TYPE_BOTH);
    static void prepare_stats();

    static void show_stats();
    static void show_runtime_memory_stats();

    static ProfilerNodeMap& get_profiler_nodes();

    static snort::ProfileStats* get_total_perf_stats();
    static snort::ProfileStats* get_other_perf_stats();
};

#endif
