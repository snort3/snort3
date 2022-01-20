//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// perf_monitor.h author Puneeth Kumar C V <puneetku@cisco.com>

#ifndef PERF_MONITOR_H
#define PERF_MONITOR_H

#include "managers/inspector_manager.h"
#include "protocols/packet.h"

#include "base_tracker.h"
#include "cpu_tracker.h"
#include "flow_ip_tracker.h"
#include "flow_tracker.h"
#include "perf_module.h"

class FlowIPDataHandler;

class PerfMonitor : public snort::Inspector
{
public:
    PerfMonitor(PerfConfig*);
    ~PerfMonitor() override { delete config; }

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;

    void eval(snort::Packet*) override;
    bool ready_to_process(snort::Packet* p);

    void tinit() override;
    void tterm() override;

    void rotate();

    void swap_constraints(PerfConstraints*);
    PerfConstraints* get_original_constraints();

    void enable_profiling(PerfConstraints*);
    void disable_profiling(PerfConstraints*);

    FlowIPTracker* get_flow_ip();

    inline PerfConstraints* get_constraints()
    { return config->constraints; }

    inline bool is_flow_ip_enabled()
    { return config->constraints->flow_ip_enabled; }

private:
    PerfConfig* const config;
    void disable_tracker(size_t);
};

#endif

