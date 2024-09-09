//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// appid_module.h author davis mcpherson <davmcphe@cisco.com>
// Created on: May 10, 2016

#ifndef APPID_MODULE_H
#define APPID_MODULE_H

#include <unordered_map>
#include <vector>

#include "framework/module.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/reload_tuner.h"

#include "appid_config.h"
#include "appid_peg_counts.h"

namespace snort
{
struct SnortConfig;
class Trace;
}

extern THREAD_LOCAL snort::ProfileStats appid_perf_stats;
extern THREAD_LOCAL snort::ProfileStats tp_appid_perf_stats;
extern THREAD_LOCAL const snort::Trace* appid_trace;

#define MOD_NAME "appid"
#define MOD_HELP "application and service identification"
#define MOD_USAGE snort::Module::GLOBAL

class AppIdReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit AppIdReloadTuner(size_t memcap) : memcap(memcap) { }
    ~AppIdReloadTuner() override = default;

    bool tinit() override;
    bool tune_packet_context() override
    {
        return tune_resources( max_work );
    }
    bool tune_idle_context() override
    {
        return tune_resources( max_work_idle );
    }

    friend class AppIdModule;

private:
    size_t memcap;

    bool tune_resources(unsigned work_limit);
};

extern THREAD_LOCAL AppIdStats appid_stats;

class AppIdModule : public snort::Module
{
public:
    AppIdModule();
    ~AppIdModule() override;

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const snort::Command* get_commands() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile(
        unsigned i, const char*& name, const char*& parent) const override;

    AppIdConfig* get_data();

    void reset_stats() override;

    Usage get_usage() const override
    { return MOD_USAGE; }
    void sum_stats(bool) override;
    void show_dynamic_stats() override;

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    AppIdConfig* config = nullptr;
};

class ACThirdPartyAppIdCleanup : public snort::AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "THIRD_PARTY_APPID_CLEANUP"; }
};

#endif
