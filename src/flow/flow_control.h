//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef FLOW_CONTROL_H
#define FLOW_CONTROL_H

#include "flow/flow.h"
#include "utils/stats.h"

struct FlowConfig
{   
    uint64_t mem_cap;
    uint32_t max_sessions;
    uint16_t cache_pruning_timeout;
    uint16_t cache_nominal_timeout;
};

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

    Flow* find_flow(const FlowKey*);
    Flow* new_flow(const FlowKey*);

    void init_tcp(const FlowConfig&, InspectSsnFunc);
    void init_udp(const FlowConfig&, InspectSsnFunc);
    void init_icmp(const FlowConfig&, InspectSsnFunc);
    void init_ip(const FlowConfig&, InspectSsnFunc);
    void init_exp(const FlowConfig& tcp, const FlowConfig& udp);

    void delete_flow(const FlowKey*);
    void delete_flow(Flow*, const char* why);
    void purge_flows(uint8_t proto);
    void prune_flows(uint8_t proto, Packet*);
    void timeout_flows(uint32_t flowCount, time_t cur_time);

    char expected_flow (Flow*, Packet*);
    bool is_expected(Packet*);

    int add_expected(
        const sfip_t *srcIP, uint16_t srcPort,
        const sfip_t *dstIP, uint16_t dstPort,
        uint8_t protocol, char direction,
        FlowData*);

    int add_expected(
        const sfip_t *srcIP, uint16_t srcPort,
        const sfip_t *dstIP, uint16_t dstPort,
        uint8_t protocol, int16_t appId, FlowData*,
        unsigned stream_callback_id = 0, Stream_Event = SE_MAX);

    uint32_t max_flows(uint8_t proto);

    PegCount get_prunes(uint8_t);
    PegCount get_flows(uint8_t);
    void clear_counts();

private:
    class FlowCache* get_cache(uint8_t);
    void set_key(FlowKey*, Packet*);

    unsigned process(Flow*, Packet*);

private:
    FlowCache* tcp_cache;
    FlowCache* udp_cache;
    FlowCache* icmp_cache;
    FlowCache* ip_cache;

    Flow* tcp_mem;
    Flow* udp_mem;
    Flow* icmp_mem;
    Flow* ip_mem;

    InspectSsnFunc get_tcp;
    InspectSsnFunc get_udp;
    InspectSsnFunc get_icmp;
    InspectSsnFunc get_ip;

    class ExpectCache* exp_cache;
};

#endif

