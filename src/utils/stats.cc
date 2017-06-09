//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stats.h"

#include "detection/detection_engine.h"
#include "file_api/file_stats.h"
#include "filters/sfthreshold.h"
#include "helpers/process.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "packet_io/trough.h"
#include "profiler/profiler.h"
#include "protocols/packet_manager.h"
#include "time/timersub.h"

#include "util.h"

#define STATS_SEPARATOR \
    "--------------------------------------------------"

static DAQ_Stats_t g_daq_stats;
static AuxCount gaux;

THREAD_LOCAL PacketCount pc;
THREAD_LOCAL AuxCount aux_counts;
ProcessCount proc_stats;

PegCount get_packet_number()
{ return pc.total_from_daq; }

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

static inline void LogSeparator(FILE* fh = stdout)
{
    LogMessage(fh, "%s\n", STATS_SEPARATOR);
}

void LogLabel(const char* s, FILE* fh)
{
    if ( *s == ' ' )
    {
        LogMessage(fh, "%s\n", s);
    }
    else
    {
        LogSeparator(fh);
        LogMessage(fh, "%s\n", s);
    }
}

void LogValue(const char* s, const char* v, FILE* fh)
{
    LogMessage(fh, "%25.25s: %s\n", s, v);
}

void LogCount(const char* s, uint64_t c, FILE* fh)
{
    if ( c )
        LogMessage(fh, "%25.25s: " STDu64 "\n", s, c);
}

void LogStat(const char* s, uint64_t n, uint64_t tot, FILE* fh)
{
    if ( n )
        LogMessage(fh, "%25.25s: " FMTu64("-12") "\t(%7.3f%%)\n", s, n, CalcPct(n, tot));
}

void LogStat(const char* s, double d, FILE* fh)
{
    if ( d )
        LogMessage(fh, "%25.25s: %g\n", s, d);
}

//-------------------------------------------------------------------------

static struct timeval starttime, endtime;

void TimeStart()
{
    gettimeofday(&starttime, NULL);
}

void TimeStop()
{
    gettimeofday(&endtime, NULL);
}

static void timing_stats()
{
    struct timeval difftime;
    TIMERSUB(&endtime, &starttime, &difftime);

    uint32_t tmp = (uint32_t)difftime.tv_sec;
    uint32_t total_secs = tmp;
    if ( total_secs < 1 )
        total_secs = 1;

    uint32_t hrs  = tmp / SECONDS_PER_HOUR;
    tmp  = tmp % SECONDS_PER_HOUR;

    uint32_t mins = tmp / SECONDS_PER_MIN;
    uint32_t secs = tmp % SECONDS_PER_MIN;

    LogLabel("timing");

    LogMessage("%25.25s: %02d:%02d:%02d\n", "runtime", hrs, mins, secs);

    LogMessage("%25.25s: %lu.%lu\n", "seconds",
        (unsigned long)difftime.tv_sec, (unsigned long)difftime.tv_usec);

    PegCount num_pkts = g_daq_stats.hw_packets_received;
    LogMessage("%25.25s: " STDu64 "\n", "packets", num_pkts);

    uint64_t pps = (num_pkts / total_secs);
    LogMessage("%25.25s: " STDu64 "\n", "pkts/sec", pps);
}

//-------------------------------------------------------------------------
// FIXIT-L need better encapsulation of these daq counts by their modules

const PegInfo daq_names[] =
{
    { "pcaps", "total files and interfaces processed" },
    { "received", "total packets received from DAQ" },
    { "analyzed", "total packets analyzed from DAQ" },
    { "dropped", "packets dropped" },
    { "filtered", "packets filtered out" },
    { "outstanding", "packets unprocessed" },
    { "injected", "active responses or replacements" },
    { "allow", "total allow verdicts" },
    { "block", "total block verdicts" },
    { "replace", "total replace verdicts" },
    { "whitelist", "total whitelist verdicts" },
    { "blacklist", "total blacklist verdicts" },
    { "ignore", "total ignore verdicts" },

    // FIXIT-L these are not exactly DAQ counts - but they are related
    { "internal_blacklist", "packets blacklisted internally due to lack of DAQ support" },
    { "internal_whitelist", "packets whitelisted internally due to lack of DAQ support" },
    { "skipped", "packets skipped at startup" },
    { "idle", "attempts to acquire from DAQ without available packets" },
    { "rx_bytes", "total bytes received" },
    { nullptr, nullptr }
};

const PegInfo pc_names[] =
{
    { "analyzed", "packets sent to detection" },
    { "hard_evals", "non-fast pattern rule evaluations" },
    { "raw_searches", "fast pattern searches in raw packet data" },
    { "cooked_searches", "fast pattern searches in cooked packet data" },
    { "pkt_searches", "fast pattern searches in packet data" },
    { "alt_searches", "alt fast pattern searches in packet data" },
    { "key_searches", "fast pattern searches in key buffer" },
    { "header_searches", "fast pattern searches in header buffer" },
    { "body_searches", "fast pattern searches in body buffer" },
    { "file_searches", "fast pattern searches in file buffer" },
    { "offloads", "fast pattern searches that were offloaded" },
    { "alerts", "alerts not including IP reputation" },
    { "total_alerts", "alerts including IP reputation" },
    { "logged", "logged packets" },
    { "passed", "passed packets" },
    { "match_limit", "fast pattern matches not processed" },
    { "queue_limit", "events not queued because queue full" },
    { "log_limit", "events queued but not logged" },
    { "event_limit", "events filtered" },
    { "alert_limit", "events previously triggered on same PDU" },
    { nullptr, nullptr }
};

const PegInfo proc_names[] =
{
    { "local_commands", "total local commands processed" },
    { "remote_commands", "total remote commands processed" },
    { "signals", "total signals processed" },
    { "conf_reloads", "number of times configuration was reloaded" },
    { "daq_reloads", "number of times daq configuration was reloaded" },
    { "attribute_table_reloads", "number of times hosts table was reloaded" },
    { "attribute_table_hosts", "total number of hosts in table" },
    { nullptr, nullptr }
};

//-------------------------------------------------------------------------

void pc_sum()
{
    // must sum explicitly; can't zero; daq stats are cumulative ...
    const DAQ_Stats_t* daq_stats = SFDAQ::get_stats();

    g_daq_stats.hw_packets_received += daq_stats->hw_packets_received;
    g_daq_stats.hw_packets_dropped += daq_stats->hw_packets_dropped;
    g_daq_stats.packets_received += daq_stats->packets_received;
    g_daq_stats.packets_filtered += daq_stats->packets_filtered;
    g_daq_stats.packets_injected += daq_stats->packets_injected;

    for ( unsigned i = 0; i < MAX_SFDAQ_VERDICT; i++ )
        g_daq_stats.verdicts[i] += daq_stats->verdicts[i];

    sum_stats((PegCount*)&gaux, (PegCount*)&aux_counts, sizeof(aux_counts)/sizeof(PegCount));

    //  FIXIT-H why do we set gaux in sum_stats then zero it here?
    memset(&gaux, 0, sizeof(gaux));
}

//-------------------------------------------------------------------------

void get_daq_stats(DAQStats& daq_stats)
{
    uint64_t pkts_recv = g_daq_stats.hw_packets_received;
    uint64_t pkts_drop = g_daq_stats.hw_packets_dropped;
    uint64_t pkts_inj = g_daq_stats.packets_injected + Active::get_injects();

    uint64_t pkts_out = 0;

    if ( pkts_recv > g_daq_stats.packets_filtered + g_daq_stats.packets_received )
        pkts_out = pkts_recv - g_daq_stats.packets_filtered - g_daq_stats.packets_received;

    daq_stats.pcaps = Trough::get_file_count();
    daq_stats.received = pkts_recv;
    daq_stats.analyzed = g_daq_stats.packets_received;
    daq_stats.dropped =  pkts_drop;
    daq_stats.filtered =  g_daq_stats.packets_filtered;
    daq_stats.outstanding =  pkts_out;
    daq_stats.injected =  pkts_inj;

    for ( unsigned i = 0; i < MAX_SFDAQ_VERDICT; i++ )
        daq_stats.verdicts[i] = g_daq_stats.verdicts[i];

    daq_stats.internal_blacklist = gaux.internal_blacklist;
    daq_stats.internal_whitelist = gaux.internal_whitelist;
    daq_stats.skipped = snort_conf->pkt_skip;
    daq_stats.idle = gaux.idle;
    daq_stats.rx_bytes = gaux.rx_bytes;
}

void DropStats()
{
    DAQStats daq_stats;
    get_daq_stats(daq_stats);

    LogLabel("Packet Statistics");
    show_stats((PegCount*)&daq_stats, daq_names, array_size(daq_names)-1, "daq");

    PacketManager::dump_stats();

    LogLabel("Module Statistics");
    const char* exclude = "daq snort";
    ModuleManager::dump_stats(snort_conf, exclude);

    file_stats_print();

    LogLabel("Summary Statistics");
    show_stats((PegCount*)&proc_stats, proc_names, array_size(proc_names)-1, "process");

    if ( SnortConfig::log_verbose() )
        log_malloc_info();
}

//-------------------------------------------------------------------------

void PrintStatistics()
{
    DropStats();
    timing_stats();

    // FIXIT-L below stats need to be made consistent with above
    print_thresholding(snort_conf->threshold_config, 1);

    {
        // FIXIT-L can do flag saving with RAII (much cleaner)
        int save_quiet_flag = snort_conf->logging_flags & LOGGING_FLAG__QUIET;

        snort_conf->logging_flags &= ~LOGGING_FLAG__QUIET;

        // once more for the main thread
        Profiler::consolidate_stats();
        Profiler::show_stats();

        snort_conf->logging_flags |= save_quiet_flag;
    }
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

static bool show_stat(
    bool head, PegCount count, const char* name, const char* module_name,
    FILE* fh = stdout)
{
    if ( !count )
        return head;

    if ( module_name && !head )
    {
        LogLabel(module_name, fh);
        head = true;
    }

    LogCount(name, count, fh);
    return head;
}

void show_stats(
    PegCount* pegs, const PegInfo* info, unsigned n, const char* module_name)
{
    bool head = false;

    for ( unsigned i = 0; i < n; ++i )
        head = show_stat(head, pegs[i], info[i].name, module_name);
}

void show_stats(
    PegCount* pegs, const PegInfo* info,
    IndexVec& peg_idxs, const char* module_name, FILE* fh)
{
    bool head = false;

    for ( auto& i : peg_idxs)
        head = show_stat(head, pegs[i], info[i].name, module_name, fh);
}

void show_percent_stats(
    PegCount* pegs, const char* names[], unsigned n, const char* module_name)
{
    bool head = false;

    for ( unsigned i = 0; i < n; ++i )
    {
        PegCount c = pegs[i];
        const char* s = names[i];

        if ( !c )
            continue;

        if ( module_name && !head )
        {
            LogLabel(module_name);
            head = true;
        }

        LogStat(s, c, pegs[0], stdout);
    }
}

