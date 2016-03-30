//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
** Marc Norton <mnorton@sourcefire.com>
** Dan Roelker <droelker@sourcefire.com>
**
*/

#ifndef PERF_FLOW_H
#define PERF_FLOW_H

#include "perf_module.h"
#include "main/snort_types.h"
#include "hash/sfxhash.h"
#include "sfip/sfip_t.h"
#include "protocols/packet.h"

#define MAX_PKT_LEN  9000
#define MAX_PORT     UINT16_MAX

enum FlowType
{
    SFS_TYPE_TCP = 0,
    SFS_TYPE_UDP,
    SFS_TYPE_OTHER,
    SFS_TYPE_MAX
};

enum FlowState
{
    SFS_STATE_TCP_ESTABLISHED = 0,
    SFS_STATE_TCP_CLOSED,
    SFS_STATE_UDP_CREATED,
    SFS_STATE_MAX
};

struct PortFlow
{
    double tot_perc[MAX_PORT+1];
    double sport_rate[MAX_PORT+1];
    double dport_rate[MAX_PORT+1];
};

struct IcmpFlow
{
    double tot_perc[256];
    int display[256];
};

/* Raw flow statistics */
struct RawFlowStats
{
    time_t time;
    uint64_t* pkt_len_cnt;
    uint64_t pkt_total;

    uint64_t byte_total;

    uint64_t* pkt_len_percent;

    uint64_t* port_tcp_src;
    uint64_t* port_tcp_dst;
    uint64_t* port_udp_src;
    uint64_t* port_udp_dst;

    uint64_t* type_icmp;

    uint64_t port_tcp_high;
    uint64_t port_tcp_total;

    uint64_t port_udp_high;
    uint64_t port_udp_total;

    uint64_t type_icmp_total;
};

/* Processed flow statistics */
struct FlowStats
{
    time_t time;
    double pkt_len_percent[MAX_PKT_LEN + 2];
    int pkt_len_percent_count;

    double traffic_tcp;
    double traffic_udp;
    double traffic_icmp;
    double traffic_other;

    PortFlow port_flow_tcp;
    double port_flow_high_tcp;
    int port_flow_tcp_count;

    PortFlow port_flow_udp;
    double port_flow_high_udp;;
    int port_flow_udp_count;

    IcmpFlow flow_icmp;
    int flow_icmp_count;
};

struct TrafficStats
{
    uint64_t packets_a_to_b;
    uint64_t bytes_a_to_b;
    uint64_t packets_b_to_a;
    uint64_t bytes_b_to_a;
};

struct FlowStateValue
{
    TrafficStats traffic_stats[SFS_TYPE_MAX];
    uint64_t total_packets;
    uint64_t total_bytes;
    uint32_t state_changes[SFS_STATE_MAX];
};

/*
**  Functions for the performance functions to call
*/
void update_flow_stats(RawFlowStats*, Packet*);
void process_flow_stats(RawFlowStats*, FILE*, PerfFormat, time_t);
void free_flow_stats(RawFlowStats*);
void log_flow_perf_header(FILE*);

#endif

