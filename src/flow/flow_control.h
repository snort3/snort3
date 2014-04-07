/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef FLOW_CONTROL_H
#define FLOW_CONTROL_H

#include "flow/flow.h"
#include "stream5/stream_common.h"

class FlowControl {
public:
    FlowControl(const Stream5Config*);
    ~FlowControl();

public:
    void process_tcp(Stream5Config*, Packet*);
    void process_udp(Stream5Config*, Packet*);
    void process_icmp(Stream5Config*, Packet*);
    void process_ip(Stream5Config*, Packet*);

    Flow* get_flow(const FlowKey*);
    Flow* new_flow(const FlowKey*);

    void delete_flow(const FlowKey*);
    void delete_flow(Flow*, const char* why);
    void purge_flows(int proto);
    void prune_flows(int proto, Packet*);
    void timeout_flows(uint32_t flowCount, time_t cur_time);

    char expected_flow (Flow*, Packet*);
    bool is_expected(Packet*);

    int add_expected(
        snort_ip* srcIP, uint16_t srcPort,
        snort_ip* dstIP, uint16_t dstPort,
        uint8_t protocol, char direction,
        FlowData*);

    int add_expected(
        snort_ip* srcIP, uint16_t srcPort,
        snort_ip* dstIP, uint16_t dstPort,
        uint8_t protocol, int16_t appId,
        FlowData*);

    uint32_t max_flows(int proto);
    void get_prunes(int proto, PegCount&);
    void reset_prunes(int proto);

private:
    void init_tcp(const Stream5Config*);
    void init_udp(const Stream5Config*);
    void init_icmp(const Stream5Config*);
    void init_ip(const Stream5Config*);
    void init_exp(const Stream5Config*);

    class FlowCache* get_cache(int proto);
    void set_key(FlowKey*, const Packet*);

    void process(FlowCache*, Stream5Config*, void*, Packet*);

private:
    FlowCache* tcp_cache;
    FlowCache* udp_cache;
    FlowCache* icmp_cache;
    FlowCache* ip_cache;
    class ExpectCache* exp_cache;
};

#endif

