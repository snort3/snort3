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

// flow_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#include "flow_tracker.h"
#include "perf_module.h"

#include "utils/util.h"

THREAD_LOCAL FlowTracker* perf_flow;

FlowTracker::FlowTracker(PerfConfig* perf) : PerfTracker(perf,
        perf->output == PERF_FILE ? FLOW_FILE : nullptr) { }

FlowTracker::~FlowTracker()
{
    if (stats.pkt_len_cnt)
    {
        free(stats.pkt_len_cnt);
        stats.pkt_len_cnt = nullptr;
    }

    if (stats.port_tcp_src)
    {
        free(stats.port_tcp_src);
        stats.port_tcp_src = nullptr;
    }

    if (stats.port_tcp_dst)
    {
        free(stats.port_tcp_dst);
        stats.port_tcp_dst = nullptr;
    }

    if (stats.port_udp_src)
    {
        free(stats.port_udp_src);
        stats.port_udp_src = nullptr;
    }

    if (stats.port_udp_dst)
    {
        free(stats.port_udp_dst);
        stats.port_udp_dst = nullptr;
    }

    if (stats.type_icmp)
    {
        free(stats.type_icmp);
        stats.type_icmp = nullptr;
    }
}

void FlowTracker::reset()
{
    static THREAD_LOCAL bool first = true;

    if (first)
    {
        stats.pkt_len_cnt = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (MAX_PKT_LEN + 2));
        stats.port_tcp_src = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (MAX_PORT+1));
        stats.port_tcp_dst = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (MAX_PORT+1));
        stats.port_udp_src = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (MAX_PORT+1));
        stats.port_udp_dst = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (MAX_PORT+1));
        stats.type_icmp = (uint64_t*)SnortAlloc(sizeof(uint64_t) * 256);

        if ( config->format == PERF_CSV )
            log_flow_perf_header(fh);

        first = false;
    }
    else
    {
        memset(stats.pkt_len_cnt, 0, sizeof(uint64_t) * (MAX_PKT_LEN + 2));
        memset(stats.port_tcp_src, 0, sizeof(uint64_t) * (MAX_PORT+1));
        memset(stats.port_tcp_dst, 0, sizeof(uint64_t) * (MAX_PORT+1));
        memset(stats.port_udp_src, 0, sizeof(uint64_t) * (MAX_PORT+1));
        memset(stats.port_udp_dst, 0, sizeof(uint64_t) * (MAX_PORT+1));
        memset(stats.type_icmp, 0, sizeof(uint64_t) * 256);
    }

    stats.pkt_total = 0;
    stats.byte_total = 0;

    stats.port_tcp_high=0;
    stats.port_tcp_total=0;

    stats.port_udp_high=0;
    stats.port_udp_total=0;

    stats.type_icmp_total = 0;
}

void FlowTracker::update(Packet* p)
{
    if (!p->is_rebuilt())
        update_flow_stats(&stats, p);
}

void FlowTracker::process(bool)
{
    process_flow_stats(&stats, fh, config->format, cur_time);

    if (!(config->perf_flags & PERF_SUMMARY))
        reset();
}

