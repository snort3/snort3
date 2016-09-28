//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <sys/time.h>
#include <sys/types.h>

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <vector>

#include "main/thread.h"
#include "main/snort_types.h"
#include "framework/counts.h"
#include "tics/tics_macro_enabler.h"

typedef std::vector<unsigned> IndexVec;

// FIXIT-L split this out into appropriate modules
struct PacketCount
{
#ifdef TICS_USE_RXP_MATCH
    PegCount tics_rxp_searches;
    PegCount tics_raw_searches;
    PegCount tics_cooked_searches;
    PegCount tics_pkt_searches;
    PegCount tics_alt_searches;
    PegCount tics_key_searches;
    PegCount tics_header_searches;
    PegCount tics_body_searches;
    PegCount tics_file_searches;
    PegCount tics_scan_portgroup_cnt;
    PegCount tics_scan_pm_type_pkt_cnt;
    PegCount tics_scan_pm_type_alt_cnt;
    PegCount tics_scan_pm_type_key_cnt;
    PegCount tics_scan_pm_type_header_cnt;
    PegCount tics_scan_pm_type_body_cnt;
    PegCount tics_scan_pm_type_file_cnt;
    PegCount tics_match_limit_reach;
    PegCount tics_scan_errors;
    PegCount tics_rxp_len_err_searches;
    PegCount tics_hs_searches;
    PegCount tics_hs_pkt_len_searches;
    PegCount tics_hs_rxp_err_searches;
    PegCount tics_hs_pkt_searches;
    PegCount tics_hs_key_searches;
    PegCount tics_hs_header_searches;
    PegCount tics_hs_file_searches;
    PegCount tics_hs_body_searches;
    PegCount tics_hs_alt_searches;
#endif /* TICS_USE_RXP_MATCH */
    PegCount total_from_daq;
    PegCount slow_searches;
    PegCount raw_searches;
    PegCount cooked_searches;
    PegCount pkt_searches;
    PegCount alt_searches;
    PegCount key_searches;
    PegCount header_searches;
    PegCount body_searches;
    PegCount file_searches;
    PegCount alert_pkts;
    PegCount total_alert_pkts;
    PegCount log_pkts;
    PegCount pass_pkts;
    PegCount match_limit;
    PegCount queue_limit;
    PegCount log_limit;
    PegCount event_limit;
    PegCount alert_limit;
};

struct ProcessCount
{
    PegCount local_commands;
    PegCount remote_commands;
    PegCount signals;
    PegCount conf_reloads;
    PegCount attribute_table_reloads;
    PegCount attribute_table_hosts;
};

struct AuxCount
{
    PegCount internal_blacklist;
    PegCount internal_whitelist;
    PegCount idle;
};

//-------------------------------------------------------------------------
// FIXIT-L 2.0.4 introduces the retry verdict
// no way to reliably optionally leverage this with dynamic loaded daqs

// FIXIT-L daq stats should be moved to sfdaq

#define MAX_SFDAQ_VERDICT 6

struct DAQStats
{
    PegCount pcaps;
    PegCount received;
    PegCount analyzed;
    PegCount dropped;
    PegCount filtered;
    PegCount outstanding;
    PegCount injected;
    PegCount verdicts[MAX_SFDAQ_VERDICT];
    PegCount internal_blacklist;
    PegCount internal_whitelist;
    PegCount skipped;
    PegCount idle;
};

extern ProcessCount proc_stats;
extern THREAD_LOCAL AuxCount aux_counts;
extern SO_PUBLIC THREAD_LOCAL PacketCount pc;

extern const PegInfo daq_names[];
extern const PegInfo pc_names[];
extern const PegInfo proc_names[];

SO_PUBLIC PegCount get_packet_number();

SO_PUBLIC void LogLabel(const char*, FILE* = stdout);
SO_PUBLIC void LogValue(const char*, const char*, FILE* = stdout);
SO_PUBLIC void LogCount(const char*, uint64_t, FILE* = stdout);

SO_PUBLIC void LogStat(const char*, uint64_t n, uint64_t tot, FILE* = stdout);
SO_PUBLIC void LogStat(const char*, double, FILE* = stdout);

void get_daq_stats(DAQStats& daq_stats);

void sum_stats(PegCount* sums, PegCount* counts, unsigned n);
void show_stats(PegCount*, const PegInfo*, unsigned n, const char* module_name = nullptr);
void show_stats( PegCount*, const PegInfo*, IndexVec&, const char* module_name, FILE*);
void show_percent_stats(PegCount*, const char*[], unsigned n, const char* module_name = nullptr);

void sum_stats(SimpleStats* sums, SimpleStats* counts);
void show_stats(SimpleStats*, const char* module_name);

double CalcPct(uint64_t, uint64_t);
void DropStats();
void pc_sum();
void pc_accum();
void PrintStatistics();
void TimeStart();
void TimeStop();

#endif

