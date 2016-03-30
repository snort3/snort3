//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// flow_ip_tracker.h author Carter Waxman <cwaxman@cisco.com>

#ifndef FLOW_IP_TRACKER_H
#define FLOW_IP_TRACKER_H

#include "perf_tracker.h"
#include "perf_flow.h"
#include "hash/sfxhash.h"

class FlowIPTracker : public PerfTracker
{
public:
    FlowIPTracker(PerfConfig* perf);
    ~FlowIPTracker();

    void reset() override;
    void update(Packet*) override;
    void process(bool) override;

    int update_state(const sfip_t* src_addr, const sfip_t* dst_addr, FlowState);

private:
    SFXHASH* ipMap;

    FlowStateValue* find_stats(const sfip_t* src_addr, const sfip_t* dst_addr, int* swapped);
    void write_stats();
    void display_stats();
};

extern THREAD_LOCAL FlowIPTracker* perf_flow_ip;
#endif

