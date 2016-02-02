//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <string>

#include "perf_monitor.h"
#include "perf_module.h"

#include "main/analyzer.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "parser/parser.h"
#include "packet_io/sfdaq.h"
#include "profiler/profiler.h"
#include "framework/inspector.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "base_tracker.h"
#include "flow_tracker.h"
#include "flow_ip_tracker.h"
#include "event_tracker.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

THREAD_LOCAL SimpleStats pmstats;
THREAD_LOCAL ProfileStats perfmonStats;

int perfmon_rotate_perf_file = 0;
static SFPERF config;
SFPERF* perfmon_config = &config;   //FIXIT-M remove this after flowip can be decoupled.
THREAD_LOCAL std::vector<PerfTracker*>* trackers;

static bool ready_to_process(Packet* p);

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
};

PerfMonitor::PerfMonitor(PerfMonModule* mod)
{
    mod->get_config(config);
    perfmon_config = &config;

    BaseTracker::so_init();
}

PerfMonitor::~PerfMonitor ()
{
    BaseTracker::so_term();
}

void PerfMonitor::show(SnortConfig*)
{
    LogMessage("PerfMonitor config:\n");
    LogMessage("  Sample Time:      %d seconds\n", config.sample_interval);
    LogMessage("  Packet Count:     %d\n", config.pkt_cnt);
    LogMessage("  Max File Size:    " STDu64 "\n", config.max_file_size);
    LogMessage("  Base Stats:       %s%s\n",
        config.perf_flags & SFPERF_BASE ? "ACTIVE" : "INACTIVE",
        config.perf_flags & SFPERF_SUMMARY_BASE ? " (SUMMARY)" : "");
    if (config.perf_flags & SFPERF_BASE)
    {
        LogMessage("    Base Stats File:  %s\n",
            config.file ? BASE_FILE : "INACTIVE");
        LogMessage("    Max Perf Stats:   %s\n",
            (config.perf_flags & SFPERF_MAX_BASE_STATS) ? "ACTIVE" : "INACTIVE");
    }
    LogMessage("  Flow Stats:       %s%s\n",
        config.perf_flags & SFPERF_FLOW ? "ACTIVE" : "INACTIVE",
        config.perf_flags & SFPERF_SUMMARY_FLOW ? " (SUMMARY)" : "");
    if (config.perf_flags & SFPERF_FLOW)
    {
        LogMessage("    Max Flow Port:    %u\n", config.flow_max_port_to_track);
        LogMessage("    Flow File:        %s\n",
            config.flow_file ? FLOW_FILE : "INACTIVE");
    }
    LogMessage("  Event Stats:      %s%s\n",
        config.perf_flags & SFPERF_EVENT ? "ACTIVE" : "INACTIVE",
        config.perf_flags & SFPERF_SUMMARY_EVENT ? " (SUMMARY)" : "");
    LogMessage("  Flow IP Stats:    %s%s\n",
        config.perf_flags & SFPERF_FLOWIP ? "ACTIVE" : "INACTIVE",
        config.perf_flags & SFPERF_SUMMARY_FLOWIP ? " (SUMMARY)" : "");
    if (config.perf_flags & SFPERF_FLOWIP)
    {
        LogMessage("    Flow IP Memcap:   %u\n", config.flowip_memcap);
        LogMessage("    Flow IP File:     %s\n",
            config.flowip_file ? FLIP_FILE : "INACTIVE");
    }
    LogMessage("  Console Mode:     %s\n",
        (config.perf_flags & SFPERF_CONSOLE) ? "ACTIVE" : "INACTIVE");
}

// FIXIT-L perfmonitor should be logging to one file and writing record type and
// version fields immediately after timestamp like
// seconds, usec, type, version#, data1, data2, ...
bool PerfMonitor::configure(SnortConfig*)
{
    return BaseTracker::so_configure();
}

void PerfMonitor::tinit()
{
    trackers = new std::vector<PerfTracker*>();

    if (config.perf_flags & SFPERF_BASE)
        trackers->push_back(new BaseTracker(&config));

    if (config.perf_flags & SFPERF_FLOW)
        trackers->push_back(perf_flow = new FlowTracker(&config));

    if (config.perf_flags & SFPERF_FLOWIP)
        trackers->push_back(perf_flow_ip = new FlowIPTracker(&config));

    if (config.perf_flags & SFPERF_EVENT)
        trackers->push_back(perf_event = new EventTracker(&config));

    for (unsigned int i = 0; i < trackers->size(); i++)
        trackers->at(i)->open(true);

    //FIXIT-M: move this
#ifdef LINUX_SMP
    sfInitProcPidStats(&(sfBase.sfProcPidStats));
#endif

    for (unsigned int i = 0; i < trackers->size(); i++)
        trackers->at(i)->reset();
}

void PerfMonitor::tterm()
{
    perf_flow = nullptr;
    perf_flow_ip = nullptr;
    perf_event = nullptr;

    while (!trackers->empty())
    {
        auto back = trackers->back();
        back->process(true);
        back->close();
        delete back;
        trackers->pop_back();
    }
    delete trackers;
}

void PerfMonitor::eval(Packet* p)
{
    Profile profile(perfmonStats);

    static THREAD_LOCAL bool first = true;

    if (first)
    {
        /*
        //FIXIT-H: FIND A HOME FOR THIS
        if (SnortConfig::read_mode())
        {
            perfBase->sfBase.pkt_stats.pkts_recv = pc.total_from_daq;
            perfBase->sfBase.pkt_stats.pkts_drop = 0;
        }
        else
        {
            const DAQ_Stats_t* ps = DAQ_GetStats();
            perfBase->sfBase.pkt_stats.pkts_recv = ps->hw_packets_received;
            perfBase->sfBase.pkt_stats.pkts_drop = ps->hw_packets_dropped;
        }
        */
        first = false;
    }

    if (IsSetRotatePerfFileFlag())
    {
        for (unsigned int i = 0; i < trackers->size(); i++)
            trackers->at(i)->rotate();
        ClearRotatePerfFileFlag();
    }

    for (unsigned int i = 0; i < trackers->size(); i++)
        trackers->at(i)->update(p);

    if ((config.perf_flags & SFPERF_TIME_COUNT) && !p->is_rebuilt())
    {
        if (ready_to_process(p))
        {
            for (unsigned int i = 0; i < trackers->size(); i++)
            {
                trackers->at(i)->process(false);
                trackers->at(i)->auto_rotate();
            }
        }
    }
    ++pmstats.total_packets;
}

static bool ready_to_process(Packet* p)
{
    static THREAD_LOCAL time_t sample_time = 0;
    static THREAD_LOCAL uint64_t cnt = 0;

    if (sample_time == 0)
        sample_time = p->pkth->ts.tv_sec;

    if ( ++cnt >= config.pkt_cnt )
    {
        if ((p->pkth->ts.tv_sec - sample_time) >= config.sample_interval)
        {
            cnt = 0;
            sample_time = p->pkth->ts.tv_sec;
            return true;
        }
    }
    return false;
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

#ifdef UNIT_TEST
TEST_CASE("Process timing logic", "[perfmon]")
{
    Packet p;
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;

    config.pkt_cnt = 0;
    config.sample_interval = 0;
    pkth.ts.tv_sec = 0;
    REQUIRE(ready_to_process(&p) == true);
    pkth.ts.tv_sec = 1;
    REQUIRE(ready_to_process(&p) == true);

    config.pkt_cnt = 2;
    config.sample_interval = 0;
    pkth.ts.tv_sec = 2;
    REQUIRE(ready_to_process(&p) == false);
    pkth.ts.tv_sec = 3;
    REQUIRE(ready_to_process(&p) == true);

    config.pkt_cnt = 0;
    config.sample_interval = 2;
    pkth.ts.tv_sec = 4;
    REQUIRE(ready_to_process(&p) == false);
    pkth.ts.tv_sec = 8;
    REQUIRE(ready_to_process(&p) == true);
    pkth.ts.tv_sec = 10;
    REQUIRE(ready_to_process(&p) == true);

    config.pkt_cnt = 5;
    config.sample_interval = 4;
    pkth.ts.tv_sec = 11;
    REQUIRE(ready_to_process(&p) == false);
    pkth.ts.tv_sec = 14;
    REQUIRE(ready_to_process(&p) == false);
    REQUIRE(ready_to_process(&p) == false);
    REQUIRE(ready_to_process(&p) == false);
    REQUIRE(ready_to_process(&p) == true);
}
#endif
