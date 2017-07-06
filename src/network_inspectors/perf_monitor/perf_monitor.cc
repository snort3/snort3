//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "perf_monitor.h"

#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "base_tracker.h"
#include "cpu_tracker.h"
#include "flow_ip_tracker.h"
#include "flow_tracker.h"

#ifdef UNIT_TEST
#include "catch/catch.hpp"
#endif

THREAD_LOCAL SimpleStats pmstats;
THREAD_LOCAL ProfileStats perfmonStats;

THREAD_LOCAL bool perfmon_rotate_perf_file = false;
static PerfConfig config;
PerfConfig* perfmon_config = &config;   // FIXIT-M remove this after flowip can be decoupled.
static THREAD_LOCAL std::vector<PerfTracker*>* trackers;

static bool ready_to_process(Packet* p);

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class PerfMonitor : public Inspector
{
public:
    PerfMonitor(PerfMonModule*);

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
}

void PerfMonitor::show(SnortConfig*)
{
    LogMessage("PerfMonitor config:\n");
    LogMessage("  Sample Time:      %d seconds\n", config.sample_interval);
    LogMessage("  Packet Count:     %d\n", config.pkt_cnt);
    LogMessage("  Max File Size:    " STDu64 "\n", config.max_file_size);
    LogMessage("  Summary Mode:     %s\n",
        (config.perf_flags & PERF_SUMMARY) ? "ACTIVE" : "INACTIVE");
    LogMessage("  Base Stats:       %s\n",
        (config.perf_flags & PERF_BASE) ? "ACTIVE" : "INACTIVE");
    LogMessage("  Flow Stats:       %s\n",
        (config.perf_flags & PERF_FLOW) ? "ACTIVE" : "INACTIVE");
    if (config.perf_flags & PERF_FLOW)
    {
        LogMessage("    Max Flow Port:    %u\n", config.flow_max_port_to_track);
    }
    LogMessage("  Event Stats:      %s\n",
        (config.perf_flags & PERF_EVENT) ? "ACTIVE" : "INACTIVE");
    LogMessage("  Flow IP Stats:    %s\n",
        (config.perf_flags & PERF_FLOWIP) ? "ACTIVE" : "INACTIVE");
    if (config.perf_flags & PERF_FLOWIP)
    {
        LogMessage("    Flow IP Memcap:   %u\n", config.flowip_memcap);
    }
    LogMessage("  CPU Stats:    %s\n",
        (config.perf_flags & PERF_CPU) ? "ACTIVE" : "INACTIVE");
    switch(config.output)
    {
        case PERF_CONSOLE:
            LogMessage("    Output Location:  console\n");
            break;
        case PERF_FILE:
            LogMessage("    Output Location:  file\n");
            break;
    }
    switch(config.format)
    {
        case PERF_TEXT:
            LogMessage("    Output Format:  text\n");
            break;
        case PERF_CSV:
            LogMessage("    Output Format:  csv\n");
            break;
        case PERF_JSON:
            LogMessage("    Output Format:  json\n");
            break;
#ifdef HAVE_FLATBUFFERS
        case PERF_FBS:
            LogMessage("    Output Format:  flatbuffers\n");
            break;
#endif
        default: break;
    }
}

static void disable_tracker(size_t i)
{
    WarningMessage("Disabling %s\n", (*trackers)[i]->get_name().c_str());
    auto tracker = trackers->at(i);
    (*trackers)[i] = (*trackers)[trackers->size() - 1];
    trackers->pop_back();
    delete tracker;
}

// FIXIT-L perfmonitor should be logging to one file and writing record
// type and version fields immediately after timestamp like seconds, usec,
// type, version#, data1, data2, ...

bool PerfMonitor::configure(SnortConfig*)
{
    return true;
}

void PerfMonitor::tinit()
{
    trackers = new std::vector<PerfTracker*>();

    if (config.perf_flags & PERF_BASE)
        trackers->push_back(new BaseTracker(&config));

    if (config.perf_flags & PERF_FLOW)
        trackers->push_back(new FlowTracker(&config));

    if (config.perf_flags & PERF_FLOWIP)
        trackers->push_back(perf_flow_ip = new FlowIPTracker(&config));

    if (config.perf_flags & PERF_CPU )
        trackers->push_back(new CPUTracker(&config));

    for (unsigned i = 0; i < trackers->size(); i++)
    {
        if (!(*trackers)[i]->open(true))
            disable_tracker(i--);
    }

    for (auto& tracker : *trackers)
        tracker->reset();
}

void PerfMonitor::tterm()
{
    perf_flow_ip = nullptr;

    if (trackers)
    {
        while (!trackers->empty())
        {
            auto back = trackers->back();
            if ( config.perf_flags & PERF_SUMMARY )
                back->process(true);
            delete back;
            trackers->pop_back();
        }
        delete trackers;
    }
}

void PerfMonitor::eval(Packet* p)
{
    Profile profile(perfmonStats);

    if (IsSetRotatePerfFileFlag())
    {
        for (unsigned i = 0; i < trackers->size(); i++)
        {
            if (!(*trackers)[i]->rotate())
                disable_tracker(i--);
        }

        ClearRotatePerfFileFlag();
    }

    if (p)
    {
        for (auto& tracker : *trackers)
        {
            tracker->update(p);
            tracker->update_time(p->pkth->ts.tv_sec);
        }
    }

    if ( (!p || !p->is_rebuilt()) && !(config.perf_flags & PERF_SUMMARY) )
    {
        if (ready_to_process(p))
        {
            for (unsigned i = 0; i < trackers->size(); i++)
            {
                (*trackers)[i]->process(false);
                if (!(*trackers)[i]->auto_rotate())
                    disable_tracker(i--);
            }
        }
    }

    if (p)
        ++pmstats.total_packets;
}

//FIXIT-M uncouple from Snort class when framework permits
void perf_monitor_idle_process()
{
    PerfMonitor* pm =
    (PerfMonitor*)InspectorManager::get_inspector("perf_monitor", true);

    if ( pm )
        pm->eval(nullptr);
}

static bool ready_to_process(Packet* p)
{
    static THREAD_LOCAL time_t sample_time = 0;
    static THREAD_LOCAL time_t cur_time = 0;
    static THREAD_LOCAL uint64_t cnt = 0;

    // FIXIT-M find a more graceful way to handle idle processing being called prior to receiving
    // packets and issues with more general lack of synchronization between OS time and incoming
    // packet timestamps.
    if (p)
    {
        cnt++;
        cur_time = p->pkth->ts.tv_sec;
    }
    else if (cur_time)
        cur_time = time(nullptr);
    else
        return false;

    if (!sample_time)
        sample_time = cur_time;

    if ( cnt >= config.pkt_cnt )
    {
        if ((cur_time - sample_time) >= config.sample_interval)
        {
            cnt = 0;
            sample_time = cur_time;
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
{ return new PerfMonitor((PerfMonModule*)m); }

static void pm_dtor(Inspector* p)
{ delete p; }

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
    Packet p(false);
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
