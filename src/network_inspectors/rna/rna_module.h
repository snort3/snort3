//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
#include "profiler/profiler.h"

#include "rna_config.h"

#define RNA_NAME "rna"
#define RNA_HELP "Real-time network awareness and OS fingerprinting (experimental)"

struct RnaStats
{
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
};

extern THREAD_LOCAL RnaStats rna_stats;
extern THREAD_LOCAL snort::ProfileStats rna_perf_stats;

class RnaModule : public snort::Module
{
public:
    RnaModule();
    ~RnaModule() override;

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    RnaModuleConfig* get_config();
    PegCount* get_counts() const override;
    const PegInfo* get_pegs() const override;
    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return CONTEXT; }

private:
    RnaModuleConfig* mod_conf = nullptr;
};

#endif
