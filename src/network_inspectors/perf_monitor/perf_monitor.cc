//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"
#include "hash/hash_defs.h"
#include "hash/xhash.h"
#include "log/messages.h"
#include "main/analyzer_command.h"
#include "main/thread.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/intrinsic_event_ids.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

THREAD_LOCAL PerfPegStats pmstats;
THREAD_LOCAL ProfileStats perfmonStats;

static THREAD_LOCAL std::vector<PerfTracker*>* trackers;
static THREAD_LOCAL FlowIPTracker* flow_ip_tracker = nullptr;

static THREAD_LOCAL PerfConstraints* t_constraints;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class PerfIdleHandler : public DataHandler
{
public:
    PerfIdleHandler(PerfMonitor& p, SnortConfig& sc) : DataHandler(PERF_NAME), perf_monitor(p)
    { DataBus::subscribe_global(intrinsic_pub_key, IntrinsicEventIds::THREAD_IDLE, this, sc); }

    void handle(DataEvent&, Flow*) override
    { perf_monitor.eval(nullptr); }

private:
    PerfMonitor& perf_monitor;
};

class PerfRotateHandler : public DataHandler
{
public:
    PerfRotateHandler(PerfMonitor& p, SnortConfig& sc) : DataHandler(PERF_NAME), perf_monitor(p)
    { DataBus::subscribe_global(intrinsic_pub_key, IntrinsicEventIds::THREAD_ROTATE, this, sc); }

    void handle(DataEvent&, Flow*) override
    { perf_monitor.rotate(); }

private:
    PerfMonitor& perf_monitor;
};

class FlowIPDataHandler : public DataHandler
{
public:
    FlowIPDataHandler(PerfMonitor& p, SnortConfig& sc) : DataHandler(PERF_NAME), perf_monitor(p)
    { DataBus::subscribe_global(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_CHANGE, this, sc); }

    void handle(DataEvent&, Flow* flow) override
    {
        FlowIPTracker* tracker = perf_monitor.get_flow_ip();

        if (!tracker)
            return;

        FlowState state = SFS_STATE_MAX;

        if ( flow->pkt_type == PktType::UDP )
            state = SFS_STATE_UDP_CREATED;

        if ( flow->pkt_type == PktType::TCP )
        {
            if ( flow->get_session_flags() & SSNFLAG_COUNTED_ESTABLISH )
                state = SFS_STATE_TCP_ESTABLISHED;

            if ( flow->get_session_flags() & SSNFLAG_COUNTED_CLOSED )
                state = SFS_STATE_TCP_CLOSED;
        }

        if ( state == SFS_STATE_MAX )
            return;

        tracker->update_state(&flow->client_ip, &flow->server_ip, state);
    }

private:
    PerfMonitor& perf_monitor;
};

PerfMonitor::PerfMonitor(PerfConfig* pcfg) : config(pcfg)
{ assert (config != nullptr); }

static const char* to_string(const PerfOutput& po)
{
    switch (po)
    {
    case PerfOutput::TO_CONSOLE:
        return "console";
    case PerfOutput::TO_FILE:
        return "file";
    }

    return "";
}

static const char* to_string(const PerfFormat& pf)
{
    switch (pf)
    {
    case PerfFormat::TEXT:
        return "text";
    case PerfFormat::CSV:
        return "csv";
    case PerfFormat::JSON:
        return "json";
    case PerfFormat::MOCK:
        return "mock";
    }

    return "";
}

void PerfMonitor::show(const SnortConfig*) const
{
    ConfigLogger::log_flag("base", config->perf_flags & PERF_BASE);
    ConfigLogger::log_flag("cpu", config->perf_flags & PERF_CPU);
    ConfigLogger::log_flag("summary", config->perf_flags & PERF_SUMMARY);

    if ( ConfigLogger::log_flag("flow", config->perf_flags & PERF_FLOW) )
        ConfigLogger::log_value("flow_ports", config->flow_max_port_to_track);

    if ( ConfigLogger::log_flag("flow_ip", config->perf_flags & PERF_FLOWIP) )
        ConfigLogger::log_value("flow_ip_memcap", config->flowip_memcap);

    ConfigLogger::log_value("packets", config->pkt_cnt);
    ConfigLogger::log_value("seconds", config->sample_interval);
    ConfigLogger::log_value("max_file_size", config->max_file_size);

    ConfigLogger::log_value("output", to_string(config->output));
    ConfigLogger::log_value("format", to_string(config->format));
}

void PerfMonitor::disable_tracker(size_t i)
{
    WarningMessage("Disabling %s\n", (*trackers)[i]->get_name().c_str());
    auto tracker = trackers->at(i);

    if ( tracker == flow_ip_tracker )
        flow_ip_tracker = nullptr;

    (*trackers)[i] = (*trackers)[trackers->size() - 1];
    trackers->pop_back();
    delete tracker;
}

// FIXIT-L perfmonitor should be logging to one file and writing record
// type and version fields immediately after timestamp like seconds, usec,
// type, version#, data1, data2, ...

bool PerfMonitor::configure(SnortConfig* sc)
{
    new PerfIdleHandler(*this, *sc);
    new PerfRotateHandler(*this, *sc);
    new FlowIPDataHandler(*this, *sc);

    return config->resolve();
}

void PerfMonitor::tinit()
{
    trackers = new std::vector<PerfTracker*>();

    t_constraints = config->constraints;

    if (config->perf_flags & PERF_BASE)
        trackers->emplace_back(new BaseTracker(config));

    if (config->perf_flags & PERF_FLOW)
        trackers->emplace_back(new FlowTracker(config));

    flow_ip_tracker = new FlowIPTracker(config);
    if (config->perf_flags & PERF_FLOWIP)
        trackers->emplace_back(flow_ip_tracker);

    if (config->perf_flags & PERF_CPU )
        trackers->emplace_back(new CPUTracker(config));

    for (unsigned i = 0; i < trackers->size(); i++)
    {
        if (!(*trackers)[i]->open(true))
            disable_tracker(i--);
    }

    for (auto& tracker : *trackers)
        tracker->reset();
}

bool PerfMonReloadTuner::tinit()
{
    PerfMonitor* pm = (PerfMonitor*)InspectorManager::get_inspector(PERF_NAME, true);
    auto* new_constraints = pm->get_constraints();

    if (new_constraints->flow_ip_enabled)
    {
        pm->enable_profiling(new_constraints);
        return flow_ip_tracker->initialize(memcap);
    }
    else
        pm->disable_profiling(new_constraints);

    return false;
}

bool PerfMonReloadTuner::tune_resources(unsigned work_limit)
{
    if (t_constraints->flow_ip_enabled)
    {
        unsigned num_freed = 0;
        int result = flow_ip_tracker->get_ip_map()->tune_memory_resources(work_limit, num_freed);
        pmstats.flow_tracker_reload_deletes += num_freed;
        return (result == HASH_OK);
    }

    return true;
}

void PerfMonitor::tterm()
{
    if (trackers)
    {
        while (!trackers->empty())
        {
            auto back = trackers->back();
            if ( config->perf_flags & PERF_SUMMARY )
                back->process(true);
            if (back == flow_ip_tracker)
                flow_ip_tracker = nullptr;
            delete back;
            trackers->pop_back();
        }
        delete trackers;
        if (flow_ip_tracker)
        {
            delete flow_ip_tracker;
            flow_ip_tracker = nullptr;
        }
    }
}

void PerfMonitor::rotate()
{
    for ( unsigned i = 0; i < trackers->size(); i++ )
        if ( !(*trackers)[i]->rotate() )
            disable_tracker(i--);
}

void PerfMonitor::swap_constraints(PerfConstraints* constraints)
{
    PerfConstraints* tmp = config->constraints;

    config->constraints = constraints;
    delete tmp;
}

PerfConstraints* PerfMonitor::get_original_constraints()
{
    auto* new_constraints = new PerfConstraints(false, config->sample_interval,
        config->pkt_cnt);

    return new_constraints;
}

void PerfMonitor::enable_profiling(PerfConstraints* constraints)
{
    t_constraints = constraints;

    auto itr = std::find(trackers->begin(), trackers->end(), flow_ip_tracker);

    if (itr != trackers->end())
        return;

    trackers->emplace_back(flow_ip_tracker);

    if (!flow_ip_tracker->is_open())
        flow_ip_tracker->open(true);
}

void PerfMonitor::disable_profiling(PerfConstraints* constraints)
{
    t_constraints = constraints;

    auto itr = std::find(trackers->begin(), trackers->end(), flow_ip_tracker);

    if (itr != trackers->end())
    {
        trackers->erase(itr);
        flow_ip_tracker->close();
    }
}

void PerfMonitor::eval(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(perfmonStats);

    if (p)
    {
        for (auto& tracker : *trackers)
        {
            tracker->update(p);
            tracker->update_time(p->pkth->ts.tv_sec);
        }
    }

    if ( (!p || !p->is_rebuilt()) && !(config->perf_flags & PERF_SUMMARY) )
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

bool PerfMonitor::ready_to_process(Packet* p)
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

    if ( cnt >= t_constraints->pkt_cnt )
    {
        if ((cur_time - sample_time) >= t_constraints->sample_interval)
        {
            if (!p)
                for (auto& tracker : *trackers)
                    tracker->update_time(cur_time);

            cnt = 0;
            sample_time = cur_time;
            return true;
        }
    }
    return false;
}

FlowIPTracker* PerfMonitor::get_flow_ip()
{ return t_constraints->flow_ip_enabled ? flow_ip_tracker : nullptr; }

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new PerfMonModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* pm_ctor(Module* m)
{ return new PerfMonitor(((PerfMonModule*)m)->get_config()); }

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
    PROTO_BIT__ANY_TYPE,
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

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_perf_monitor[] =
#endif
{
    &pm_api.base,
    nullptr
};

#ifdef UNIT_TEST
TEST_CASE("Process timing logic", "[perfmon]")
{
    PerfMonModule mod;
    PerfConfig* config = new PerfConfig;
    mod.set_config(config);
    PerfMonitor perfmon(mod.get_config());

    Packet p(false);
    DAQ_PktHdr_t pkth;
    p.pkth = &pkth;

    t_constraints = config->constraints;

    t_constraints->pkt_cnt = 0;
    t_constraints->sample_interval = 0;
    pkth.ts.tv_sec = 0;
    REQUIRE((perfmon.ready_to_process(&p) == true));
    pkth.ts.tv_sec = 1;
    REQUIRE((perfmon.ready_to_process(&p) == true));

    t_constraints->pkt_cnt = 2;
    t_constraints->sample_interval = 0;
    pkth.ts.tv_sec = 2;
    REQUIRE((perfmon.ready_to_process(&p) == false));
    pkth.ts.tv_sec = 3;
    REQUIRE((perfmon.ready_to_process(&p) == true));

    t_constraints->pkt_cnt = 0;
    t_constraints->sample_interval = 2;
    pkth.ts.tv_sec = 4;
    REQUIRE((perfmon.ready_to_process(&p) == false));
    pkth.ts.tv_sec = 8;
    REQUIRE((perfmon.ready_to_process(&p) == true));
    pkth.ts.tv_sec = 10;
    REQUIRE((perfmon.ready_to_process(&p) == true));

    t_constraints->pkt_cnt = 5;
    t_constraints->sample_interval = 4;
    pkth.ts.tv_sec = 11;
    REQUIRE((perfmon.ready_to_process(&p) == false));
    pkth.ts.tv_sec = 14;
    REQUIRE((perfmon.ready_to_process(&p) == false));
    REQUIRE((perfmon.ready_to_process(&p) == false));
    REQUIRE((perfmon.ready_to_process(&p) == false));
    REQUIRE((perfmon.ready_to_process(&p) == true));
}
#endif
