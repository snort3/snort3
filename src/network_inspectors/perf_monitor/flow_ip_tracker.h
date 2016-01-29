//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
#include "hash/sfxhash.h"

struct sfSFSKey
{
    sfip_t ipA;
    sfip_t ipB;
};

struct sfBTStats
{
    uint64_t packets_AtoB;
    uint64_t bytes_AtoB;
    uint64_t packets_BtoA;
    uint64_t bytes_BtoA;
};

struct sfSFSValue
{
    sfBTStats trafficStats[SFS_TYPE_MAX];
    uint64_t total_packets;
    uint64_t total_bytes;
    uint32_t stateChanges[SFS_STATE_MAX];
};

class FlowIPTracker : public PerfTracker
{
public:
    FlowIPTracker(SFPERF* perf);
    ~FlowIPTracker();

    void reset() override;
    void update(Packet*) override;
    void process(bool) override;

    int updateState(const sfip_t* src_addr, const sfip_t* dst_addr, SFSState state);

private:
    SFXHASH* ipMap;

    sfSFSValue* findFlowIPStats(const sfip_t* src_addr, const sfip_t* dst_addr, int* swapped);
    void WriteFlowIPStats();
    void DisplayFlowIPStats();
};

extern THREAD_LOCAL FlowIPTracker* perf_flow_ip;
#endif

