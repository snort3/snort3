//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef STATS_H
#define STATS_H

// Provides facilities for displaying Snort exit stats

#include <daq_common.h>
#include <cstdio>
#include <vector>

#include "framework/counts.h"
#include "main/snort_types.h"

class ControlConn;

// FIXIT-L split this out into appropriate modules
struct PacketCount
{
    PegCount analyzed_pkts;
    PegCount hard_evals;
    PegCount raw_searches;
    PegCount cooked_searches;
    PegCount pkt_searches;
    PegCount alt_searches;
    PegCount pdu_searches;
    PegCount file_searches;
    PegCount offloads;
    PegCount alert_pkts;
    PegCount total_alert_pkts;
    PegCount log_pkts;
    PegCount pass_pkts;
    PegCount match_limit;
    PegCount queue_limit;
    PegCount log_limit;
    PegCount event_limit;
    PegCount alert_limit;
    PegCount context_stalls;
    PegCount offload_busy;
    PegCount onload_waits;
    PegCount offload_fallback;
    PegCount offload_failures;
    PegCount offload_suspends;
    PegCount cont_creations;
    PegCount cont_recalls;
    PegCount cont_flows;
    PegCount cont_evals;
    PegCount cont_matches;
    PegCount cont_mismatches;
    PegCount cont_max_num;
    PegCount cont_match_distance;
    PegCount cont_mismatch_distance;
    PegCount buf_dumps;
};

struct ProcessCount
{
    PegCount local_commands;
    PegCount remote_commands;
    PegCount signals;
    PegCount conf_reloads;
    PegCount policy_reloads;
    PegCount inspector_deletions;
    PegCount daq_reloads;
    PegCount attribute_table_reloads;
    PegCount attribute_table_hosts;     // FIXIT-D - remove when host attribute pegs updated
    PegCount attribute_table_overflow;  // FIXIT-D - remove when host attribute pegs updated
};

extern ProcessCount proc_stats;

extern const PegInfo daq_names[];
extern const PegInfo pc_names[];
extern const PegInfo proc_names[];

namespace snort
{
extern THREAD_LOCAL PacketCount pc;
}

void sum_stats(PegCount* sums, PegCount* counts, unsigned n, bool dump_stats = false);
void show_stats(PegCount*, const PegInfo*, const char* module_name = nullptr);
void show_stats(PegCount*, const PegInfo*, unsigned n, const char* module_name = nullptr);
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char* module_name, FILE*);
void show_percent_stats(PegCount*, const char*[], unsigned n, const char* module_name = nullptr);

void sum_stats(SimpleStats* sums, SimpleStats* counts);
void show_stats(SimpleStats*, const char* module_name);

void DropStats(ControlConn* ctrlcon = nullptr);
void PrintStatistics();
void TimeStart();
void TimeStop();
const struct timeval& get_time_curr();
const struct timeval& get_time_start();
const struct timeval& get_time_end();

#endif
