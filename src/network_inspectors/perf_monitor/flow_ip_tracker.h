//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "hash/xhash.h"

enum FlowState
{
    SFS_STATE_TCP_ESTABLISHED = 0,
    SFS_STATE_TCP_CLOSED,
    SFS_STATE_UDP_CREATED,
    SFS_STATE_MAX
};

enum FlowType
{
    SFS_TYPE_TCP = 0,
    SFS_TYPE_UDP,
    SFS_TYPE_OTHER,
    SFS_TYPE_MAX
};

struct TrafficStats
{
    PegCount  packets_a_to_b;
    PegCount  bytes_a_to_b;
    PegCount  packets_b_to_a;
    PegCount  bytes_b_to_a;
};

struct FlowStateValue
{
    TrafficStats traffic_stats[SFS_TYPE_MAX];
    PegCount total_packets;
    PegCount total_bytes;
    PegCount state_changes[SFS_STATE_MAX];
};

class FlowIPTracker : public PerfTracker
{
public:
    FlowIPTracker(PerfConfig* perf);
    ~FlowIPTracker() override;

    void reset() override;
    void update(snort::Packet*) override;
    void process(bool) override;

    int update_state(const snort::SfIp* src_addr, const snort::SfIp* dst_addr, FlowState);

private:
    FlowStateValue stats;
    snort::XHash* ip_map;
    char ip_a[41], ip_b[41];

    FlowStateValue* find_stats(const snort::SfIp* src_addr, const snort::SfIp* dst_addr, int* swapped);
    void write_stats();
    void display_stats();
};
#endif

