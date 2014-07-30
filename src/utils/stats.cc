/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "stats.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <timersub.h>

#include "snort.h"
#include "util.h"
#include "packet_io/sfdaq.h"
#include "packet_io/active.h"
#include "packet_io/trough.h"
#include "target_based/sftarget_reader.h"
#include "managers/module_manager.h"
#include "managers/packet_manager.h"

#define STATS_SEPARATOR \
    "--------------------------------------------------"

static DAQ_Stats_t g_daq_stats;
static PacketCount gpc;
THREAD_LOCAL PacketCount pc;
ProcessCount proc_stats;

//-------------------------------------------------------------------------

double CalcPct(uint64_t cnt, uint64_t total)
{
    double pct = 0.0;

    if (total == 0.0)
    {
        pct = (double)cnt;
    }
    else
    {
        pct = (double)cnt / (double)total;
    }

    pct *= 100.0;

    return pct;
}

//-------------------------------------------------------------------------

static inline void LogSeparator()
{
    LogMessage("%s\n", STATS_SEPARATOR);
}

void LogLabel(const char* s)
{
    if ( *s == ' ' )
    {
        LogMessage("%s\n", s);
    }
    else
    {
        LogSeparator();
        LogMessage("%s statistics\n", s);
    }
}

void LogCount (const char* s, uint64_t c)
{
    LogMessage("%25.25s: " STDu64 "\n", s, c);
}

void LogStat (const char* s, uint64_t n, uint64_t tot)
{
#ifdef VALGRIND_TESTING
    LogMessage("%25.25s: " FMTu64("-12") "\n", s, n);
#else
    LogMessage("%25.25s: " FMTu64("-12") "\t(%7.3f%%)\n", s, n, CalcPct(n, tot));
#endif
}

void LogStat (const char* s, double d)
{
    LogMessage("%25.25s: %g\n", s, d);
}

//-------------------------------------------------------------------------

static struct timeval starttime, endtime;

void TimeStart (void)
{
    gettimeofday(&starttime, NULL);
}

void TimeStop (void)
{
    gettimeofday(&endtime, NULL);
}

static void timing_stats()
{
    struct timeval difftime;
    TIMERSUB(&endtime, &starttime, &difftime);

    uint32_t tmp = (uint32_t)difftime.tv_sec;
    uint32_t total_secs = tmp;
    if ( total_secs < 1 ) total_secs = 1;

    uint32_t hrs  = tmp / SECONDS_PER_HOUR;
    tmp  = tmp % SECONDS_PER_HOUR;

    uint32_t mins = tmp / SECONDS_PER_MIN;
    uint32_t secs = tmp % SECONDS_PER_MIN;

    LogLabel("timing");

    LogMessage("%25.25s: %02d:%02d:%02d\n", "runtime", hrs, mins, secs);

    LogMessage("%25.25s: %lu.%lu\n", "seconds",
        (unsigned long)difftime.tv_sec, (unsigned long)difftime.tv_usec);

    LogMessage("%25.25s: " STDu64 "\n", "packets", gpc.total_from_daq);

    uint64_t pps = (gpc.total_from_daq / total_secs);
    LogMessage("%25.25s: " STDu64 "\n", "pkts/sec", pps);
}

//-------------------------------------------------------------------------

struct DAQStats
{
    PegCount received;
    PegCount analyzed;
    PegCount dropped;
    PegCount filtered;
    PegCount outstanding;
    PegCount injected;
#ifdef REG_TEST
    PegCount skipped;
#endif
};

struct DAQVerdicts
{
    PegCount verdicts[MAX_DAQ_VERDICT];
    PegCount internal_blacklist;
    PegCount internal_whitelist;
};

//-------------------------------------------------------------------------

static const char* simple_names[] =
{
    "packets"
};

static const char* daq_names[] =
{
    "received",
    "analyzed",
    "dropped",
    "filtered",
    "outstanding",
    "injected"
#ifdef REG_TEST
    , "skipped"
#endif
};

const char* verdict_names[] =
{
    "allow",
    "block",
    "replace",
    "whitelist",
    "blacklist",
    "ignore",
    "internal blacklist",
    "internal whitelist"
};

static const char* pc_names[] =
{
    "analyzed",
    "fail open",
    "alerts",
    "total alerts",
    "logged",
    "passed",
    "match limit",
    "queue limit",
    "log limit",
    "event limit",
    "alert limit",
    "internal blacklist",
    "internal whitelist",
};

static const char* proc_names[] =
{
    "local commands",
    "remote commands",
    "signals",
    "conf reloads",
    "attribute table reloads",
    "attribute table hosts"
};

//-------------------------------------------------------------------------

void pc_sum()
{
    // must sum explicitly; can't zero; daq stats are cuumulative ...
    const DAQ_Stats_t* daq_stats = DAQ_GetStats();

    g_daq_stats.hw_packets_received += daq_stats->hw_packets_received;
    g_daq_stats.hw_packets_dropped += daq_stats->hw_packets_dropped;
    g_daq_stats.packets_received += daq_stats->packets_received;
    g_daq_stats.packets_filtered += daq_stats->packets_filtered;
    g_daq_stats.packets_injected += daq_stats->packets_injected;

    for ( unsigned i = 0; i < MAX_DAQ_VERDICT; i++ )
        g_daq_stats.verdicts[i] += daq_stats->verdicts[i];

    sum_stats((PegCount*)&gpc, (PegCount*)&pc, array_size(pc_names));
    memset(&pc, 0, sizeof(pc));
}

//-------------------------------------------------------------------------

void DropStats()
{
    const DAQ_Stats_t* pkt_stats = &g_daq_stats;

    LogLabel("Basic");

    {
        uint64_t pkts_out, pkts_inj;

        uint64_t pkts_recv = pkt_stats->hw_packets_received;
        uint64_t pkts_drop = pkt_stats->hw_packets_dropped;

        if ( pkts_recv > pkt_stats->packets_filtered
                       + pkt_stats->packets_received )
            pkts_out = pkts_recv - pkt_stats->packets_filtered
                     - pkt_stats->packets_received;
        else
            pkts_out = 0;

        pkts_inj = pkt_stats->packets_injected;
        pkts_inj += Active_GetInjects();

        DAQStats daq_stats;
        daq_stats.received = pkts_recv;
        daq_stats.analyzed = pkt_stats->packets_received;
        daq_stats.dropped =  pkts_drop;
        daq_stats.filtered =  pkt_stats->packets_filtered;
        daq_stats.outstanding =  pkts_out;
        daq_stats.injected =  pkts_inj;
#ifdef REG_TEST
        daq_stats.skipped = snort_conf->pkt_skip; 
#endif

        LogLabel("daq");
        PegCount pcaps = Trough_GetFileCount();
        if ( pcaps )
            LogCount("pcaps", pcaps);
        show_stats((PegCount*)&daq_stats, daq_names, array_size(daq_names));

        DAQVerdicts daq_verdicts;

        for ( unsigned i = 0; i < MAX_DAQ_VERDICT; i++ )
            daq_verdicts.verdicts[i] = pkt_stats->verdicts[i];

        daq_verdicts.internal_blacklist = pc.internal_blacklist;
        daq_verdicts.internal_whitelist = pc.internal_whitelist;

        show_stats((PegCount*)&daq_verdicts, verdict_names, array_size(verdict_names));
    }

    PacketManager::dump_stats();
    //mpse_print_qinfo();

    LogLabel("Modules");
    ModuleManager::dump_stats(snort_conf);

    // ensure proper counting of log_limit
    SnortEventqResetCounts();

    // FIXIT alert_pkts excludes rep hits
    if ( gpc.total_alert_pkts == gpc.alert_pkts )
        gpc.total_alert_pkts = 0;

    LogLabel("Summary");
    show_stats((PegCount*)&gpc, pc_names, array_size(pc_names), "detection");

#ifdef PPM_MGR
    PPM_PRINT_SUMMARY(&snort_conf->ppm_cfg);
#endif
    proc_stats.attribute_table_hosts = SFAT_NumberOfHosts();
    show_stats((PegCount*)&proc_stats, proc_names, array_size(proc_names), "process");
}

//-------------------------------------------------------------------------

void PrintStatistics (void)
{   
    DropStats();
    timing_stats();

    // FIXIT below stats need to be made consistent with above
    fpShowEventStats(snort_conf);
    print_thresholding(snort_conf->threshold_config, 1);

#ifdef PERF_PROFILING
    {
        int save_quiet_flag = snort_conf->logging_flags & LOGGING_FLAG__QUIET;
    
        snort_conf->logging_flags &= ~LOGGING_FLAG__QUIET;
    
        ShowAllProfiles();
    
        snort_conf->logging_flags |= save_quiet_flag;
    }
#endif
}

//-------------------------------------------------------------------------

void sum_stats(
    PegCount* gpegs, PegCount* tpegs, unsigned n)
{
    for ( unsigned i = 0; i < n; ++i )
    {
        gpegs[i] += tpegs[i];
        tpegs[i] = 0;
    }
}

void show_stats(
    PegCount* pegs, const char* names[], unsigned n, const char* module_name)
{
    if ( module_name )
        LogLabel(module_name);

    for ( unsigned i = 0; i < n; ++i )
    {
        PegCount c = pegs[i];
        const char* s = names[i];

        if ( (!module_name || i) && !c )
            continue;

        LogCount(s, c);
        // FIXIT this has alignment issues for structs cast as arrays?
        //LogCount(names[i], pegs[i]);
    }
}

void show_percent_stats(
    PegCount* pegs, const char* names[], unsigned n, const char* module_name)
{
    if ( module_name )
        LogLabel(module_name);

    for ( unsigned i = 0; i < n; ++i )
    {
        PegCount c = pegs[i];
        const char* s = names[i];

        if ( i && !c )
            continue;

        LogStat(s, c, pegs[0]);
    }
}

//-------------------------------------------------------------------------

void sum_stats(SimpleStats* sums, SimpleStats* counts)
{
    sum_stats((PegCount*)sums, (PegCount*)counts, array_size(simple_names));
}

void show_stats(SimpleStats* sums, const char* module_name)
{
    show_stats((PegCount*)sums, simple_names, array_size(simple_names), module_name);
}

