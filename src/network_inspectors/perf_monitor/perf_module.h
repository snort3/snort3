//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// perf_module.h author Russ Combs <rucombs@cisco.com>

#ifndef PERF_MODULE_H
#define PERF_MODULE_H

#include <unordered_map>

#include "framework/module.h"

#include "perf_pegs.h"
#include "perf_reload_tuner.h"

#define PERF_NAME "perf_monitor"
#define PERF_HELP "performance monitoring and flow statistics collection"

// Perf Flags
#define PERF_BASE       0x00000001
#define PERF_CPU        0x00000002
#define PERF_FLOW       0x00000004
#define PERF_FLOWIP     0x00000008
#define PERF_SUMMARY    0x00000010

#define ROLLOVER_THRESH     512
#define MAX_PERF_FILE_SIZE  UINT64_MAX
#define MIN_PERF_FILE_SIZE  4096

enum class PerfFormat
{
    CSV,
    TEXT,
    JSON,
    MOCK
};

enum class PerfOutput
{
    TO_FILE,
    TO_CONSOLE
};

struct ModuleConfig
{
    // state optimized for run time using indices
    // can't be determined until all modules have loaded (PerfMonitor::configure)
    snort::Module* ptr;
    std::vector<unsigned> pegs;

    void set_name(const std::string& name);
    void set_peg_names(snort::Value& peg_names);
    bool confirm_parse();
    bool resolve();

private:
    std::string name;
    std::unordered_map<std::string, bool> peg_names;
};

struct PerfConstraints
{
    bool flow_ip_enabled = false;
    unsigned sample_interval = 0;
    uint32_t pkt_cnt = 0;
    bool flow_ip_all = false;

    PerfConstraints() = default;
    PerfConstraints(bool en, unsigned interval, uint32_t cnt, bool lat) :
        flow_ip_enabled(en), sample_interval(interval), pkt_cnt(cnt), flow_ip_all(lat) { }
};

struct PerfConfig
{
    int perf_flags = 0;
    uint32_t pkt_cnt = 0;
    unsigned sample_interval = 0;
    uint64_t max_file_size = 0;
    int flow_max_port_to_track = 0;
    size_t flowip_memcap = 0;
    bool flow_ip_all = false;
    PerfFormat format = PerfFormat::CSV;
    PerfOutput output = PerfOutput::TO_FILE;
    std::vector<ModuleConfig> modules;
    std::vector<snort::Module*> mods_to_prep;
    PerfConstraints* constraints;

    PerfConfig() { constraints = new PerfConstraints; }
    ~PerfConfig() { delete constraints; }

    bool resolve();
};

/* The Module Class for incorporation into Snort++ */
class PerfMonModule : public snort::Module
{
public:
    PerfMonModule();
    ~PerfMonModule() override;

    const snort::Command* get_commands() const override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    PerfConfig* get_config();
#ifdef UNIT_TEST
    void set_config(PerfConfig* ptr) { config = ptr; }
#endif

    Usage get_usage() const override
    { return GLOBAL; }

private:
    PerfConfig* config = nullptr;
};

extern THREAD_LOCAL PerfPegStats pmstats;
extern THREAD_LOCAL snort::ProfileStats perfmonStats;
extern THREAD_LOCAL PerfConstraints* t_constraints;

#endif

