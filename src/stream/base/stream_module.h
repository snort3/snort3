//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// stream_module.h author Russ Combs <rucombs@cisco.com>

#ifndef STREAM_MODULE_H
#define STREAM_MODULE_H

#include "flow/flow_config.h"
#include "framework/module.h"

extern THREAD_LOCAL snort::ProfileStats s5PerfStats;

namespace snort
{
struct SnortConfig;
}

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------
extern Trace TRACE_NAME(stream);

#define MOD_NAME "stream"
#define MOD_HELP "common flow tracking"

#define PROTO_FIELDS(proto) \
    PegCount proto ## _flows; \
    PegCount proto ## _total_prunes; \
    PegCount proto ## _timeout_prunes; \
    PegCount proto ## _excess_prunes; \
    PegCount proto ## _uni_prunes; \
    PegCount proto ## _preemptive_prunes; \
    PegCount proto ## _memcap_prunes; \
    PegCount proto ## _ha_prunes

struct BaseStats
{
    PROTO_FIELDS(ip);
    PROTO_FIELDS(icmp);
    PROTO_FIELDS(tcp);
    PROTO_FIELDS(udp);
    PROTO_FIELDS(user);
    PROTO_FIELDS(file);
};

extern const PegInfo base_pegs[];

extern THREAD_LOCAL BaseStats stream_base_stats;

struct StreamModuleConfig
{
    FlowConfig ip_cfg;
    FlowConfig icmp_cfg;
    FlowConfig tcp_cfg;
    FlowConfig udp_cfg;
    FlowConfig user_cfg;
    FlowConfig file_cfg;

    int footprint;
    bool ip_frags_only;
    bool track_on_syn;
};

class StreamModule : public snort::Module
{
public:
    StreamModule();

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;
    const StreamModuleConfig* get_data();

    unsigned get_gid() const override;
    const snort::RuleMap* get_rules() const override;

    void sum_stats(bool) override;
    void show_stats() override;
    void reset_stats() override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    StreamModuleConfig config;
};

extern void base_sum();
extern void base_stats();
extern void base_reset();

#endif

