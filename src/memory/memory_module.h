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

// memory_module.h author Joel Cornett <jocornet@cisco.com>

#ifndef MEMORY_MODULE_H
#define MEMORY_MODULE_H

#include "framework/module.h"

#include <shared_mutex>

class MemoryModule : public snort::Module
{
public:
    MemoryModule();

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    void sum_stats(bool dump_stats) override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

    std::shared_mutex mem_global_stats_mutex;
};

extern THREAD_LOCAL const snort::Trace* memory_trace;

#endif

