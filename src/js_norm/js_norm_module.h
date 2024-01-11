//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// js_norm_module.h author Danylo Kyrylov <dkyrylov@cisco.com>

#ifndef JS_NORM_MODULE_H
#define JS_NORM_MODULE_H

#include "framework/module.h"
#include "main/policy.h"
#include "profiler/profiler.h"

#include "js_config.h"
#include "js_enum.h"

namespace snort
{
class Trace;
}

extern THREAD_LOCAL const snort::Trace* js_trace;

class JSNormModule : public snort::Module
{
public:
    JSNormModule();
    ~JSNormModule() override;

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

    unsigned get_gid() const override;

    const snort::RuleMap* get_rules() const override
    { return events; }

    const PegInfo* get_pegs() const override
    { return peg_names; }

    PegCount* get_counts() const override
    { return peg_counts; }

    snort::ProfileStats* get_profile() const override
    { return &profile_stats; }

    Usage get_usage() const override
    { return INSPECT; }

    static void increment_peg_counts(jsn::PEG_COUNT counter)
    { peg_counts[counter]++; }

    static void increment_peg_counts(jsn::PEG_COUNT counter, uint64_t value)
    { peg_counts[counter] += value; }

    static PegCount get_peg_counts(jsn::PEG_COUNT counter)
    { return peg_counts[counter]; }

private:
    static const snort::Parameter params[];
    static const snort::RuleMap events[];
    static const PegInfo peg_names[];

    static THREAD_LOCAL PegCount peg_counts[];
    static THREAD_LOCAL snort::ProfileStats profile_stats;

    JSNormConfig* config;
};

#endif
