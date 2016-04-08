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

#include "protocols/icmp4.h"
#include "utils/util.h"

#define FLOW_FILE (PERF_NAME "_flow.csv")

#define MAX_PKT_LEN  9000

enum FlowSecRef
{
    SR_FLOW,
    SR_TCP,
    SR_UDP,
    SR_ICMP
};

enum FlowFieldRef
{
    FR_BYTE_TOTAL = 0,
    FR_PKT_LEN_CNT,
    FR_PKT_LEN_OVER,
};

enum FlowProtoFieldRef
{
    FR_SRC_BYTES = 0,
    FR_DST_BYTES,
    FR_HIGH_BYTES,
};

enum FlowIcmpFieldRef
{
    FR_ICMP_TYPE_BYTES = 0
};

FlowTracker::FlowTracker(PerfConfig* perf) : PerfTracker(perf,
        perf->output == PERF_FILE ? FLOW_FILE : nullptr)
{
    pkt_len_cnt.resize( MAX_PKT_LEN + 1 );
    tcp.src.resize( config->flow_max_port_to_track + 1, 0 );
    tcp.dst.resize( config->flow_max_port_to_track + 1, 0 );
    udp.src.resize( config->flow_max_port_to_track + 1, 0 );
    udp.dst.resize( config->flow_max_port_to_track + 1, 0 );
    type_icmp.resize( (1 << sizeof(icmp::IcmpType)) + 1, 0 );

    formatter->register_section("flow");
    formatter->register_field("byte_total");
    formatter->register_field("packets_by_bytes");
    formatter->register_field("oversized_packets");

    formatter->register_section("flow_tcp");
    formatter->register_field("bytes_by_source");
    formatter->register_field("bytes_by_dest");
    formatter->register_field("high_port_bytes");

    formatter->register_section("flow_udp");
    formatter->register_field("bytes_by_source");
    formatter->register_field("bytes_by_dest");
    formatter->register_field("high_port_bytes");

    formatter->register_section("flow_icmp");
    formatter->register_field("bytes_by_type");
}

void FlowTracker::reset()
{
    formatter->finalize_fields(fh);
}

void FlowTracker::update(Packet* p)
{
    if (!p->is_rebuilt())
    {
        auto len = p->pkth->caplen;

        if (p->ptrs.tcph)
            update_transport_flows(p->ptrs.sp, p->ptrs.dp,
                tcp, len);
        
        else if (p->ptrs.udph)
            update_transport_flows(p->ptrs.sp, p->ptrs.dp,
                udp, len);

        else if (p->ptrs.icmph)
            type_icmp[p->ptrs.icmph->type] += len;

        if (len <= MAX_PKT_LEN)
            pkt_len_cnt[len]++;
        else
            pkt_len_oversize_cnt++;

        byte_total += len;
    }
}

void FlowTracker::process(bool)
{
    formatter->set_field(SR_FLOW, FR_BYTE_TOTAL, byte_total);
    formatter->set_field(SR_FLOW, FR_PKT_LEN_CNT, &pkt_len_cnt);
    formatter->set_field(SR_FLOW, FR_PKT_LEN_OVER, pkt_len_oversize_cnt);

    formatter->set_field(SR_TCP, FR_SRC_BYTES, &tcp.src);
    formatter->set_field(SR_TCP, FR_DST_BYTES, &tcp.dst);
    formatter->set_field(SR_TCP, FR_HIGH_BYTES, tcp.high);
    
    formatter->set_field(SR_UDP, FR_SRC_BYTES, &udp.src);
    formatter->set_field(SR_UDP, FR_DST_BYTES, &udp.dst);
    formatter->set_field(SR_UDP, FR_HIGH_BYTES, udp.high);

    formatter->set_field(SR_ICMP, FR_ICMP_TYPE_BYTES, &type_icmp);

    formatter->write(fh, cur_time);
    formatter->clear();

    byte_total = 0;

    memset(&pkt_len_cnt[0], 0, pkt_len_cnt.size() * sizeof(PegCount));
    pkt_len_oversize_cnt = 0;

    memset(&tcp.src[0], 0, tcp.src.size() * sizeof(PegCount));
    memset(&tcp.dst[0], 0, tcp.dst.size() * sizeof(PegCount));
    tcp.high = 0;

    memset(&udp.src[0], 0, udp.src.size() * sizeof(PegCount));
    memset(&udp.dst[0], 0, udp.dst.size() * sizeof(PegCount));
    udp.high = 0;
    
    memset(&type_icmp[0], 0, type_icmp.size() * sizeof(PegCount));
}

void FlowTracker::update_transport_flows(int sport, int dport,
    FlowProto& proto, int len)
{
    if (sport <= config->flow_max_port_to_track &&
        dport > config->flow_max_port_to_track)
    {
        proto.src[sport] += len;
    }

    else if (dport <= config->flow_max_port_to_track &&
        sport > config->flow_max_port_to_track)
    {
        proto.dst[dport] += len;
    }

    else if (sport <= config->flow_max_port_to_track &&
        dport <= config->flow_max_port_to_track)
    {
        proto.src[sport] += len;
        proto.dst[dport] += len;
    }

    else
    {
        proto.high += len;
    }
}
