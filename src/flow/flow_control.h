//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// flow_control.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_CONTROL_H
#define FLOW_CONTROL_H

// this is where all the flow caches are managed and where all flows are
// processed.  flows are pruned as needed to process new flows.

#include <cstdint>
#include <vector>

#include "flow/flow_config.h"
#include "framework/counts.h"
#include "framework/decode_data.h"
#include "framework/inspector.h"

class Flow;
class FlowData;
class FlowCache;
struct FlowKey;
struct Packet;
struct SfIp;

enum class PruneReason : uint8_t;

class FlowControl
{
public:
    FlowControl();
    ~FlowControl();

public:
    void process_ip(Packet*);
    void process_icmp(Packet*);
    void process_tcp(Packet*);
    void process_udp(Packet*);
    void process_user(Packet*);
    void process_file(Packet*);

    Flow* find_flow(const FlowKey*);
    Flow* new_flow(const FlowKey*);

    void init_ip(const FlowConfig&, InspectSsnFunc);
    void init_icmp(const FlowConfig&, InspectSsnFunc);
    void init_tcp(const FlowConfig&, InspectSsnFunc);
    void init_udp(const FlowConfig&, InspectSsnFunc);
    void init_user(const FlowConfig&, InspectSsnFunc);
    void init_file(const FlowConfig&, InspectSsnFunc);
    void init_exp(uint32_t max);

    void delete_flow(const FlowKey*);
    void delete_flow(Flow*, PruneReason);
    void purge_flows(PktType);
    bool prune_one(PruneReason, bool do_cleanup);

    void timeout_flows(time_t cur_time);

    bool expected_flow(Flow*, Packet*);
    bool is_expected(Packet*);

    int add_expected(
        const Packet* ctrlPkt, PktType, IpProtocol,
        const SfIp *srcIP, uint16_t srcPort,
        const SfIp *dstIP, uint16_t dstPort,
        char direction, FlowData*);

    int add_expected(
        const Packet* ctrlPkt, PktType, IpProtocol,
        const SfIp *srcIP, uint16_t srcPort,
        const SfIp *dstIP, uint16_t dstPort,
        int16_t appId, FlowData*);

    PegCount get_flows(PktType);
    PegCount get_total_prunes(PktType) const;
    PegCount get_prunes(PktType, PruneReason) const;

    void clear_counts();

private:
    FlowCache* get_cache(PktType);
    const FlowCache* get_cache(PktType) const;

    void set_key(FlowKey*, Packet*);

    unsigned process(Flow*, Packet*);
    void preemptive_cleanup();

private:
    FlowCache* ip_cache = nullptr;
    FlowCache* icmp_cache = nullptr;
    FlowCache* tcp_cache = nullptr;
    FlowCache* udp_cache = nullptr;
    FlowCache* user_cache = nullptr;
    FlowCache* file_cache = nullptr;

    // preallocated arrays
    Flow* ip_mem = nullptr;
    Flow* icmp_mem = nullptr;
    Flow* tcp_mem = nullptr;
    Flow* udp_mem = nullptr;
    Flow* user_mem = nullptr;
    Flow* file_mem = nullptr;

    InspectSsnFunc get_ip = nullptr;
    InspectSsnFunc get_icmp = nullptr;
    InspectSsnFunc get_tcp = nullptr;
    InspectSsnFunc get_udp = nullptr;
    InspectSsnFunc get_user = nullptr;
    InspectSsnFunc get_file = nullptr;

    class ExpectCache* exp_cache = nullptr;
    PktType last_pkt_type = PktType::NONE;

    std::vector<PktType> types;
    unsigned next = 0;
};

#endif

