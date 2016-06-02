//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow_config.h"
#include "framework/counts.h"
#include "framework/decode_data.h"
#include "framework/inspector.h"

class Flow;
class FlowData;
class FlowCache;
struct FlowKey;
struct Packet;
struct sfip_t;

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
    void prune_flows(PktType, const Packet*);
    bool prune_one(PruneReason, bool do_cleanup);
    void timeout_flows(uint32_t flowCount, time_t cur_time);

    char expected_flow(Flow*, Packet*);
    bool is_expected(Packet*);

    int add_expected(
        const sfip_t *srcIP, uint16_t srcPort,
        const sfip_t *dstIP, uint16_t dstPort,
        PktType, char direction, FlowData*);

    int add_expected(
        const sfip_t *srcIP, uint16_t srcPort,
        const sfip_t *dstIP, uint16_t dstPort,
        PktType, int16_t appId, FlowData*);

    uint32_t max_flows(PktType);

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
    FlowCache* ip_cache;
    FlowCache* icmp_cache;
    FlowCache* tcp_cache;
    FlowCache* udp_cache;
    FlowCache* user_cache;
    FlowCache* file_cache;

    // preallocated arrays
    Flow* ip_mem;
    Flow* icmp_mem;
    Flow* tcp_mem;
    Flow* udp_mem;
    Flow* user_mem;
    Flow* file_mem;

    InspectSsnFunc get_ip;
    InspectSsnFunc get_icmp;
    InspectSsnFunc get_tcp;
    InspectSsnFunc get_udp;
    InspectSsnFunc get_user;
    InspectSsnFunc get_file;

    class ExpectCache* exp_cache;
    PktType last_pkt_type;
};

#endif

