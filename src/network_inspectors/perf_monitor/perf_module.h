//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/module.h"

#define PERF_NAME "perf_monitor"
#define PERF_HELP "performance monitoring and flow statistics collection"

// Perf Flags
#define PERF_BASE       0x00000001
#define PERF_CPU        0x00000002
#define PERF_FLOW       0x00000004
#define PERF_EVENT      0x00000008
#define PERF_BASE_MAX   0x00000010
#define PERF_FLOWIP     0x00000020
#define PERF_SUMMARY    0x00000040

#define ROLLOVER_THRESH     512
#define MAX_PERF_FILE_SIZE  UINT64_MAX
#define MIN_PERF_FILE_SIZE  4096

enum PerfFormat
{
    PERF_CSV,
    PERF_TEXT,
    PERF_JSON,
    PERF_FBS,
    PERF_MOCK
};

enum PerfOutput
{
    PERF_FILE,
    PERF_CONSOLE
};

struct PerfConfigBase
{

    int perf_flags;
    uint32_t pkt_cnt;
    int sample_interval;
    uint64_t max_file_size;
    int flow_max_port_to_track;
    uint32_t flowip_memcap;
    PerfFormat format;
    PerfOutput output;
};

struct PerfConfig:public PerfConfigBase
{
    std::vector<Module*> modules;
    std::vector<IndexVec> mod_peg_idxs;
};

/* The Module Class for incorporation into Snort++ */
class PerfMonModule : public Module
{
public:
    PerfMonModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    void get_config(PerfConfig&);

private:
    PerfConfig config;

    std::string mod_pegs;
    std::string mod_name;
};

extern THREAD_LOCAL SimpleStats pmstats;
extern THREAD_LOCAL ProfileStats perfmonStats;

#endif

