//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
/*
**  Marc Norton <mnorton@sourcefire.com>
**  Dan Roelker <droelker@sourcefire.com>
**
**  NOTES
**  6.4.02 - Initial Source Code.  Norton/Roelker
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include <string>

#include "perf.h"
#include "perf_base.h"
#include "perf_module.h"

#include "main/analyzer.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "parser/parser.h"
#include "packet_io/sfdaq.h"
#include "time/profiler.h"
#include "framework/inspector.h"
#include "utils/stats.h"
#include "utils/util.h"

THREAD_LOCAL SFPERF* perfmon_config = nullptr;

THREAD_LOCAL SimpleStats pmstats;
THREAD_LOCAL ProfileStats perfmonStats;

/* This function changes the perfmon log files permission if exists.
   It is done in the  PerfMonitorInit() before Snort changed its user & group.
 */
// FIXIT-L this should be deleted; was added as 1-time workaround to
// get around the borked perms due to a bug that has been fixed
static void PerfMonitorChangeLogFilesPermission(void)
{
    struct stat pt;
    mode_t mode =  S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

    if (perfmon_config == NULL)
        return;

    if (perfmon_config->file != NULL)
    {
        /*Check file before change permission*/
        if (stat(perfmon_config->file, &pt) == 0)
        {
            /*Only change permission for file owned by root*/
            if ((0 == pt.st_uid) || (0 == pt.st_gid))
            {
                if (chmod(perfmon_config->file, mode) != 0)
                {
                    ParseError("perfmonitor: Unable to change mode of "
                        "base stats file '%s' to mode:%d: %s.",
                        perfmon_config->file, mode, get_error(errno));
                    return;
                }

                if (chown(perfmon_config->file, SnortConfig::get_uid(), SnortConfig::get_gid()) != 0)
                {
                    ParseError("perfmonitor: Unable to change permissions of "
                        "base stats file '%s' to user:%d and group:%d: %s.",
                        perfmon_config->file, SnortConfig::get_uid(), SnortConfig::get_gid(), get_error(errno));
                    return;
                }
            }
        }
    }

    if (perfmon_config->flow_file != NULL)
    {
        /*Check file before change permission*/
        if (stat(perfmon_config->flow_file, &pt) == 0)
        {
            /*Only change permission for file owned by root*/
            if ((0 == pt.st_uid) || (0 == pt.st_gid))
            {
                if (chmod(perfmon_config->flow_file, mode) != 0)
                {
                    ParseError("perfmonitor: Unable to change mode of "
                        "flow stats file '%s' to mode:%d: %s.",
                        perfmon_config->flow_file, mode, get_error(errno));
                    return;
                }

                if (chown(perfmon_config->flow_file, SnortConfig::get_uid(), SnortConfig::get_gid()) != 0)
                {
                    ParseError("perfmonitor: Unable to change permissions of "
                        "flow stats file '%s' to user:%d and group:%d: %s.",
                        perfmon_config->flow_file, SnortConfig::get_uid(), SnortConfig::get_gid(), get_error(errno));
                    return;
                }
            }
        }
    }

    if (perfmon_config->flowip_file != NULL)
    {
        /*Check file before change permission*/
        if (stat(perfmon_config->flowip_file, &pt) == 0)
        {
            /*Only change permission for file owned by root*/
            if ((0 == pt.st_uid) || (0 == pt.st_gid))
            {
                if (chmod(perfmon_config->flowip_file, mode) != 0)
                {
                    ParseError("perfmonitor: Unable to change mode of "
                        "flow-ip stats file '%s' to mode:%d: %s.",
                        perfmon_config->flowip_file, mode, get_error(errno));
                    return;
                }

                if (chown(perfmon_config->flowip_file, SnortConfig::get_uid(), SnortConfig::get_gid()) != 0)
                {
                    ParseError("perfmonitor: Unable to change permissions of "
                        "flow-ip stats file '%s' to user:%d and group:%d: %s.",
                        perfmon_config->flowip_file, SnortConfig::get_uid(), SnortConfig::get_gid(), get_error(errno));
                    return;
                }
            }
        }
    }
}

static void PrintConfig(SFPERF* pconfig)
{
    if ((pconfig->perf_flags & SFPERF_SUMMARY) != SFPERF_SUMMARY)
        pconfig->perf_flags |= SFPERF_TIME_COUNT;

    LogMessage("PerfMonitor config:\n");
    LogMessage("  Sample Time:      %d seconds\n", pconfig->sample_interval);
    LogMessage("  Packet Count:     %d\n", pconfig->pkt_cnt);
    LogMessage("  Max File Size:    %u\n", pconfig->max_file_size);
    LogMessage("  Base Stats:       %s%s\n",
        pconfig->perf_flags & SFPERF_BASE ? "ACTIVE" : "INACTIVE",
        pconfig->perf_flags & SFPERF_SUMMARY_BASE ? " (SUMMARY)" : "");
    if (pconfig->perf_flags & SFPERF_BASE)
    {
        LogMessage("    Base Stats File:  %s\n",
            (pconfig->file != NULL) ? pconfig->file : "INACTIVE");
        LogMessage("    Max Perf Stats:   %s\n",
            (pconfig->perf_flags & SFPERF_MAX_BASE_STATS) ? "ACTIVE" : "INACTIVE");
    }
    LogMessage("  Flow Stats:       %s%s\n",
        pconfig->perf_flags & SFPERF_FLOW ? "ACTIVE" : "INACTIVE",
        pconfig->perf_flags & SFPERF_SUMMARY_FLOW ? " (SUMMARY)" : "");
    if (pconfig->perf_flags & SFPERF_FLOW)
    {
        LogMessage("    Max Flow Port:    %u\n", pconfig->flow_max_port_to_track);
        LogMessage("    Flow File:        %s\n",
            (pconfig->flow_file != NULL) ? pconfig->flow_file : "INACTIVE");
    }
    LogMessage("  Event Stats:      %s%s\n",
        pconfig->perf_flags & SFPERF_EVENT ? "ACTIVE" : "INACTIVE",
        pconfig->perf_flags & SFPERF_SUMMARY_EVENT ? " (SUMMARY)" : "");
    LogMessage("  Flow IP Stats:    %s%s\n",
        pconfig->perf_flags & SFPERF_FLOWIP ? "ACTIVE" : "INACTIVE",
        pconfig->perf_flags & SFPERF_SUMMARY_FLOWIP ? " (SUMMARY)" : "");
    if (pconfig->perf_flags & SFPERF_FLOWIP)
    {
        LogMessage("    Flow IP Memcap:   %u\n", pconfig->flowip_memcap);
        LogMessage("    Flow IP File:     %s\n",
            (pconfig->flowip_file != NULL) ? pconfig->flowip_file : "INACTIVE");
    }
    LogMessage("  Console Mode:     %s\n",
        (pconfig->perf_flags & SFPERF_CONSOLE) ? "ACTIVE" : "INACTIVE");
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class PerfMonitor : public Inspector
{
public:
    PerfMonitor(PerfMonModule*);
    ~PerfMonitor();

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;

    void eval(Packet*) override;

    void tinit() override;
    void tterm() override;

private:
    SFPERF config;
};

PerfMonitor::PerfMonitor(PerfMonModule* mod)
{
    mod->get_config(config);
}

PerfMonitor::~PerfMonitor ()
{
    if ( config.file )
        free(config.file);

    if ( config.flow_file )
        free(config.flow_file);

    if ( config.flowip_file )
        free(config.flowip_file);
}

void PerfMonitor::show(SnortConfig*)
{
    PrintConfig(&config);
}

// FIXIT-L perfmonitor should be logging to one file and writing record type and
// version fields immediately after timestamp like
// seconds, usec, type, version#, data1, data2, ...
bool PerfMonitor::configure(SnortConfig*)
{
    PerfMonitorChangeLogFilesPermission();
    std::string name;

    if ( config.file )
    {
        const char* file = get_instance_file(name, config.file);

        if ( (config.fh = sfOpenBaseStatsFile(file)) == NULL )
        {
            ParseError("perfmonitor: Cannot open base stats file '%s'.", file);
            return false;
        }
    }

    if ( config.flow_file )
    {
        const char* file = get_instance_file(name, config.flow_file);

        if ( (config.flow_fh = sfOpenFlowStatsFile(file)) == NULL )
        {
            ParseError("perfmonitor: Cannot open flow stats file '%s'.", file);
            return false;
        }
    }

    if ( config.flowip_file )
    {
        const char* file = get_instance_file(name, config.flowip_file);

        if ( (config.flowip_fh = sfOpenFlowIPStatsFile(file)) == NULL )
        {
            ParseError("perfmonitor: Cannot open flow-ip stats file '%s'.", file);
            return false;
        }
    }
    return true;
}

void PerfMonitor::tinit()
{
    InitPerfStats(&config);
}

void PerfMonitor::tterm()
{
    if ( config.perf_flags & SFPERF_SUMMARY )
        sfPerfStatsSummary(&config);

    sfCloseBaseStatsFile(&config);
    sfCloseFlowStatsFile(&config);
    sfCloseFlowIPStatsFile(&config);

    FreeFlowStats(&sfFlow);
#ifdef LINUX_SMP
    FreeProcPidStats(&sfBase.sfProcPidStats);
#endif
}

void PerfMonitor::eval(Packet* p)
{
    static THREAD_LOCAL bool first = true;
    PROFILE_VARS;
    MODULE_PROFILE_START(perfmonStats);

    if (first)
    {
        if (SnortConfig::read_mode())
        {
            sfBase.pkt_stats.pkts_recv = pc.total_from_daq;
            sfBase.pkt_stats.pkts_drop = 0;
        }
        else
        {
            const DAQ_Stats_t* ps = DAQ_GetStats();
            sfBase.pkt_stats.pkts_recv = ps->hw_packets_received;
            sfBase.pkt_stats.pkts_drop = ps->hw_packets_dropped;
        }

        SetSampleTime(&config, p);

        first = false;
    }

    if (IsSetRotatePerfFileFlag())
    {
        sfRotateBaseStatsFile(&config);
        sfRotateFlowStatsFile(&config);
        ClearRotatePerfFileFlag();
    }

    sfPerformanceStats(&config, p);
    ++pmstats.total_packets;

    MODULE_PROFILE_END(perfmonStats);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new PerfMonModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* pm_ctor(Module* m)
{
    static THREAD_LOCAL unsigned s_init = true;

    if ( !s_init )
        return nullptr;

    return new PerfMonitor((PerfMonModule*)m);
}

static void pm_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi pm_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        PERF_NAME,
        PERF_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    (uint16_t)PktType::ANY,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    pm_ctor,
    pm_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* nin_perf_monitor = &pm_api.base;

