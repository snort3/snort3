//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// ip_module.h author Russ Combs <rucombs@cisco.com>

#ifndef IP_MODULE_H
#define IP_MODULE_H

#include "flow/session.h"
#include "framework/module.h"

namespace snort
{
class Trace;
struct SnortConfig;
}

extern THREAD_LOCAL const snort::Trace* stream_ip_trace;

#define GLOBAL_KEYWORD "defrag"
#define ENGINE_KEYWORD "defrag_engine"

#define GID_DEFRAG     123

#define DEFRAG_IPOPTIONS           1
#define DEFRAG_TEARDROP            2
#define DEFRAG_SHORT_FRAG          3
#define DEFRAG_ANOMALY_OVERSIZE    4
#define DEFRAG_ANOMALY_ZERO        5
#define DEFRAG_ANOMALY_BADSIZE_SM  6
#define DEFRAG_ANOMALY_BADSIZE_LG  7
#define DEFRAG_ANOMALY_OVLP        8

/* 123:9, 123:10 are OBE w/ addition of 116:458
 * (aka DECODE_IPV6_BAD_FRAG_PKT).
 * Leave these here so they are not reused.
 * ------
#define DEFRAG_IPV6_BSD_ICMP_FRAG  9
#define DEFRAG_IPV6_BAD_FRAG_PKT  10
 * ------
*/
#define DEFRAG_MIN_TTL_EVASION    11
#define DEFRAG_EXCESSIVE_OVERLAP  12
#define DEFRAG_TINY_FRAGMENT      13

/* statistics tracking struct */
struct IpStats
{
    SESSION_STATS;
    PegCount total_bytes;
    PegCount total;
    PegCount current_frags;
    PegCount max_frags;
    PegCount reassembles;
    PegCount discards;
    PegCount frag_timeouts;
    PegCount overlaps;
    PegCount anomalies;
    PegCount alerts;
    PegCount drops;
    PegCount trackers_created;
    PegCount trackers_released;
    PegCount trackers_cleared;
    PegCount trackers_completed;
    PegCount nodes_created;
    PegCount nodes_released;
    PegCount reassembled_bytes;
    PegCount fragmented_bytes;
};

extern const PegInfo ip_pegs[];
extern THREAD_LOCAL snort::ProfileStats ip_perf_stats;

//-------------------------------------------------------------------------
// stream_ip module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_ip"
#define MOD_HELP "stream inspector for IP flow tracking and defragmentation"

struct StreamIpConfig;

class StreamIpModule : public snort::Module
{
public:
    StreamIpModule();
    ~StreamIpModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;

    const snort::RuleMap* get_rules() const override;
    snort::ProfileStats* get_profile() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    StreamIpConfig* get_data();

    unsigned get_gid() const override
    { return GID_DEFRAG; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    StreamIpConfig* config;
};

#endif

