//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// flow_ip_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow_ip_tracker.h"

#include "hash/hash_defs.h"
#include "log/messages.h"
#include "protocols/packet.h"

#include "perf_pegs.h"

using namespace snort;

// The default number of rows used for the xhash ip_map
#define DEFAULT_XHASH_NROWS 1021
#define TRACKER_NAME PERF_NAME "_flow_ip"

struct FlowStateKey
{
    SfIp ipA;
    SfIp ipB;
};

FlowStateValue* FlowIPTracker::find_stats(const SfIp* src_addr, const SfIp* dst_addr,
    int* swapped)
{
    FlowStateKey key;
    FlowStateValue* value = nullptr;

    if ( src_addr->less_than(*dst_addr) )
    {
        key.ipA = *src_addr;
        key.ipB = *dst_addr;
        *swapped = 0;
    }
    else
    {
        key.ipA = *dst_addr;
        key.ipB = *src_addr;
        *swapped = 1;
    }

    value = (FlowStateValue*)ip_map->get_user_data(&key);
    if ( !value )
    {
        if ( ip_map->insert(&key, nullptr) != HASH_OK )
            return nullptr;
        value = (FlowStateValue*)ip_map->get_user_data();
        memset(value, 0, sizeof(FlowStateValue));
    }

    return value;
}

bool FlowIPTracker::initialize(size_t new_memcap)
{
    bool need_pruning = false;

    if ( !ip_map )
    {
        ip_map = new XHash(DEFAULT_XHASH_NROWS, sizeof(FlowStateKey),
            sizeof(FlowStateValue), new_memcap);
    }
    else
    {
        need_pruning = (new_memcap < memcap);
        memcap = new_memcap;
        ip_map->set_memcap(new_memcap);
    }

    return need_pruning;
}

FlowIPTracker::FlowIPTracker(PerfConfig* perf) : PerfTracker(perf, TRACKER_NAME),
    perf_flags(perf->perf_flags), perf_conf(perf)
{
    formatter->register_section("flow_ip");
    formatter->register_field("ip_a", ip_a);
    formatter->register_field("ip_b", ip_b);
    formatter->register_field("tcp_packets_a_b",
        &stats.traffic_stats[SFS_TYPE_TCP].packets_a_to_b);
    formatter->register_field("tcp_bytes_a_b",
        &stats.traffic_stats[SFS_TYPE_TCP].bytes_a_to_b);
    formatter->register_field("tcp_packets_b_a",
        &stats.traffic_stats[SFS_TYPE_TCP].packets_b_to_a);
    formatter->register_field("tcp_bytes_b_a",
        &stats.traffic_stats[SFS_TYPE_TCP].bytes_b_to_a);
    formatter->register_field("udp_packets_a_b",
        &stats.traffic_stats[SFS_TYPE_UDP].packets_a_to_b);
    formatter->register_field("udp_bytes_a_b",
        &stats.traffic_stats[SFS_TYPE_UDP].bytes_a_to_b);
    formatter->register_field("udp_packets_b_a",
        &stats.traffic_stats[SFS_TYPE_UDP].packets_b_to_a);
    formatter->register_field("udp_bytes_b_a",
        &stats.traffic_stats[SFS_TYPE_UDP].bytes_b_to_a);
    formatter->register_field("other_packets_a_b",
        &stats.traffic_stats[SFS_TYPE_OTHER].packets_a_to_b);
    formatter->register_field("other_bytes_a_b",
        &stats.traffic_stats[SFS_TYPE_OTHER].bytes_a_to_b);
    formatter->register_field("other_packets_b_a",
        &stats.traffic_stats[SFS_TYPE_OTHER].packets_b_to_a);
    formatter->register_field("other_bytes_b_a",
        &stats.traffic_stats[SFS_TYPE_OTHER].bytes_b_to_a);
    formatter->register_field("tcp_established", (PegCount*)
        &stats.state_changes[SFS_STATE_TCP_ESTABLISHED]);
    formatter->register_field("tcp_closed", (PegCount*)
        &stats.state_changes[SFS_STATE_TCP_CLOSED]);
    formatter->register_field("udp_created", (PegCount*)
        &stats.state_changes[SFS_STATE_UDP_CREATED]);
    formatter->finalize_fields();
    stats.total_packets = stats.total_bytes = 0;

    memcap = perf->flowip_memcap;
    ip_map = new XHash(DEFAULT_XHASH_NROWS, sizeof(FlowStateKey), sizeof(FlowStateValue), memcap);
}

FlowIPTracker::~FlowIPTracker()
{
    const XHashStats& stats = ip_map->get_stats();
    pmstats.flow_tracker_creates = stats.nodes_created;
    pmstats.flow_tracker_total_deletes = stats.memcap_deletes;
    pmstats.flow_tracker_prunes = stats.memcap_prunes;

    delete ip_map;
}

void FlowIPTracker::reset()
{ ip_map->clear_hash(); }

void FlowIPTracker::update(Packet* p)
{
    if ( p->has_ip() && !p->is_rebuilt() )
    {
        FlowType type = SFS_TYPE_OTHER;
        int swapped;

        const SfIp* src_addr = p->ptrs.ip_api.get_src();
        const SfIp* dst_addr = p->ptrs.ip_api.get_dst();
        int len = p->pktlen;

        if (p->ptrs.tcph)
            type = SFS_TYPE_TCP;
        else if (p->ptrs.udph)
            type = SFS_TYPE_UDP;

        FlowStateValue* value = find_stats(src_addr, dst_addr, &swapped);
        if ( !value )
            return;

        TrafficStats* stats = &value->traffic_stats[type];

        if ( !swapped )
        {
            stats->packets_a_to_b++;
            stats->bytes_a_to_b += len;
        }
        else
        {
            stats->packets_b_to_a++;
            stats->bytes_b_to_a += len;
        }
        value->total_packets++;
        value->total_bytes += len;
    }
}

void FlowIPTracker::process(bool)
{
    for (auto node = ip_map->find_first_node(); node; node = ip_map->find_next_node())
    {
        FlowStateKey* key = (FlowStateKey*)node->key;
        FlowStateValue* cur_stats = (FlowStateValue*)node->data;

        key->ipA.ntop(ip_a, sizeof(ip_a));
        key->ipB.ntop(ip_b, sizeof(ip_b));
        memcpy(&stats, cur_stats, sizeof(stats));

        write();
    }

    if ( !(perf_flags & PERF_SUMMARY) )
        reset();
}

int FlowIPTracker::update_state(const SfIp* src_addr, const SfIp* dst_addr, FlowState state)
{
    int swapped;

    FlowStateValue* value = find_stats(src_addr, dst_addr, &swapped);
    if ( !value )
        return 1;

    value->state_changes[state]++;
    return 0;
}

