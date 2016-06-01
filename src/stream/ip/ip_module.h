//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"
#include "main/thread.h"
#include "framework/module.h"
#include "stream/stream.h"

struct SnortConfig;

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
    PegCount total;             // total_ipfragmented_packets
    PegCount current;           // iCurrentFrags
    PegCount max_frags;         // iMaxFrags
    PegCount reassembles;       // total_ipreassembled_packets / iFragFlushes
    PegCount discards;
    PegCount frag_timeouts;     // iFragTimeouts
    PegCount overlaps;
    PegCount anomalies;
    PegCount alerts;
    PegCount drops;
    PegCount trackers_created;  // iFragCreates
    PegCount trackers_released;
    PegCount trackers_cleared;  // iFragDeletes - delete meant dump the frag list
    PegCount trackers_completed;// iFragComplete
    PegCount nodes_created;     // iFragInserts tracked a similar stat (# calls to insert)
    PegCount nodes_released;
    PegCount mem_in_use;        // frag_mem_in_use
    PegCount reassembled_bytes; // total_ipreassembled_bytes
    PegCount fragmented_bytes;  // total_ipfragmented_bytes
};

extern const PegInfo ip_pegs[];
extern THREAD_LOCAL struct IpStats ip_stats;
extern THREAD_LOCAL ProfileStats ip_perf_stats;
extern THREAD_LOCAL ProfileStats fragPerfStats;
extern THREAD_LOCAL ProfileStats fragInsertPerfStats;
extern THREAD_LOCAL ProfileStats fragRebuildPerfStats;

//-------------------------------------------------------------------------
// stream_ip module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_ip"
#define MOD_HELP "stream inspector for IP flow tracking and defragmentation"

struct StreamIpConfig;

class StreamIpModule : public Module
{
public:
    StreamIpModule();
    ~StreamIpModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const RuleMap* get_rules() const override;
    ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    StreamIpConfig* get_data();

    unsigned get_gid() const override
    { return GID_DEFRAG; }

    void sum_stats() override;

private:
    StreamIpConfig* config;
};

#endif

