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

// snort_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef SNORT_MODULE_H
#define SNORT_MODULE_H

// the snort module is for handling command line args,
// shell commands, and basic application stats

#include <set>
#include <string>

#include "framework/module.h"
#include "main/snort_types.h"

namespace snort
{
class Trace;
}

extern THREAD_LOCAL const snort::Trace* snort_trace;

enum
{
    TRACE_INSPECTOR_MANAGER = 0,
    TRACE_MAIN,
    TRACE_MIME,
};

class SnortModule : public snort::Module
{
public:
    SnortModule();

#ifdef SHELL
    const snort::Command* get_commands() const override;
#endif

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    bool global_stats() const override
    { return true; }

    void sum_stats(bool dump_stats) override
    { Module::sum_stats(dump_stats); }

    void reset_stats() override;

    snort::ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;

    Usage get_usage() const override
    { return GLOBAL; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    inline bool is(const snort::Value& v, const char* opt);

    struct SFDAQModuleConfig* module_config = nullptr;
    bool no_warn_flowbits = false;
    bool no_warn_rules = false;
    std::string stub_opts;
    std::set<std::string> cli_opts;
    bool cli_mode = true;
};

#endif

