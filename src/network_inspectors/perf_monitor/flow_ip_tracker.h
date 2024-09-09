//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "hash/xhash.h"

#include "network_inspectors/appid/application_ids.h"
#include "perf_tracker.h"

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
    char appid_name[40] = "APPID_NONE";
    uint16_t port_a = 0;
    uint16_t port_b = 0;
    uint8_t protocol = 0;
    TrafficStats traffic_stats[SFS_TYPE_MAX] = {};
    PegCount total_packets = 0;
    PegCount total_bytes = 0;
    PegCount total_flow_latency = 0;
    PegCount total_rule_latency = 0;
    PegCount state_changes[SFS_STATE_MAX] = {};
};

class FlowIPTracker : public PerfTracker
{
public:
    FlowIPTracker(PerfConfig* perf);
    ~FlowIPTracker() override;

    bool initialize(size_t new_memcap);
    void reset() override;
    void update(snort::Packet*) override;
    void process(bool) override;
    int update_state(const snort::SfIp* src_addr, const snort::SfIp* dst_addr, FlowState,
        const char* appid_name, uint16_t src_port, uint16_t dst_port, uint8_t ip_protocol,
        uint64_t flow_latency, uint64_t rule_latency);
    snort::XHash* get_ip_map()
        { return ip_map; }

private:
    FlowStateValue stats;
    snort::XHash* ip_map;
    char ip_a[41], ip_b[41], port_a[8], port_b[8], protocol[8];
    char appid_name[40] = "APPID_NONE", flow_latency[20] = {}, rule_latency[20] = {};
    int perf_flags;
    PerfConfig* perf_conf;
    size_t memcap;
    FlowStateValue* find_stats(const snort::SfIp* src_addr, const snort::SfIp* dst_addr,
        int* swapped, const char* appid_name, uint16_t src_port, uint16_t dst_port,
        uint8_t ip_protocol, uint64_t flow_latency, uint64_t rule_latency);
    void write_stats();
    void display_stats();

};
#endif

