//--------------------------------------------------------------------------
// Copyright (C) 2019-2021 Cisco and/or its affiliates. All rights reserved.
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

// rna_module.h author Masud Hasan <mashasan@cisco.com>

#ifndef RNA_MODULE_H
#define RNA_MODULE_H

#include "framework/module.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"

#include "rna_config.h"
#include "rna_fingerprint.h"
#include "rna_mac_cache.h"
#include "rna_name.h"

struct RnaStats
{
    PegCount appid_change;
    PegCount cpe_os;
    PegCount icmp_bidirectional;
    PegCount icmp_new;
    PegCount ip_bidirectional;
    PegCount ip_new;
    PegCount udp_bidirectional;
    PegCount udp_new;
    PegCount tcp_syn;
    PegCount tcp_syn_ack;
    PegCount tcp_midstream;
    PegCount other_packets;
    PegCount change_host_update;
    PegCount dhcp_data;
    PegCount dhcp_info;
    PegCount smb;
};

extern THREAD_LOCAL RnaStats rna_stats;
extern THREAD_LOCAL snort::ProfileStats rna_perf_stats;
extern THREAD_LOCAL const snort::Trace* rna_trace;


// A tuner for initializing fingerprint processors during reload
class FpProcReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit FpProcReloadTuner(RnaModuleConfig& mod_conf)
        : mod_conf(mod_conf) { }
    ~FpProcReloadTuner() override = default;

    bool tinit() override;

    bool tune_packet_context() override
    { return true; }

    bool tune_idle_context() override
    { return true; }

private:
    RnaModuleConfig& mod_conf;
};

class RnaModule : public snort::Module
{
public:
    RnaModule();
    ~RnaModule() override;

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    bool log_mac_cache(const char* outfile);

    const snort::Command* get_commands() const override;
    RnaModuleConfig* get_config();
    PegCount* get_counts() const override;
    const PegInfo* get_pegs() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return CONTEXT; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    RnaModuleConfig* mod_conf = nullptr;
    const char* dump_file = nullptr;

    RawFingerprint fingerprint;

    bool is_valid_fqn(const char* fqn) const;
};

#endif
