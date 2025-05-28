//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <appid/appid_api.h>
#include "flow/stream_flow.h"
#include "framework/pig_pen.h"
#include "hash/hash_defs.h"
#include "log/messages.h"
#include "protocols/packet.h"

#include "perf_monitor.h"
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
    int* swapped, const char* appid_name, uint16_t src_port, uint16_t dst_port,
    uint8_t ip_protocol, uint64_t flow_latency, uint64_t rule_latency)
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
    if ( value )
    {
        strncpy(value->appid_name, appid_name, sizeof(value->appid_name) - 1);
        value->appid_name[sizeof(value->appid_name) - 1] = '\0';
        if ( *swapped )
        {
            value->port_a = dst_port;
            value->port_b = src_port;
        }
        else
        {
            value->port_a = src_port;
            value->port_b = dst_port;
        }
        value->protocol = ip_protocol;
        value->total_flow_latency = flow_latency;
        value->total_rule_latency = rule_latency;
    }
    else
    {
        if ( ip_map->insert(&key, nullptr) != HASH_OK )
            return nullptr;
        value = (FlowStateValue*)ip_map->get_user_data();
        static constexpr FlowStateValue fsv_empty_value;
        *value = fsv_empty_value;
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
    formatter->register_field("app_id", appid_name);
    formatter->register_field("port_a", port_a);
    formatter->register_field("port_b", port_b);
    formatter->register_field("protocol", protocol);
    formatter->register_field("flow_latency", flow_latency);
    formatter->register_field("rule_latency", rule_latency);
    formatter->finalize_fields();
    stats.total_packets = stats.total_bytes = 0;

    memcap = perf->flowip_memcap;
    ip_map = new XHash(DEFAULT_XHASH_NROWS, sizeof(FlowStateKey), sizeof(FlowStateValue), memcap);
}

FlowIPTracker::~FlowIPTracker()
{
    const XHashStats& tmp_stats = ip_map->get_stats();
    pmstats.flow_tracker_creates = tmp_stats.nodes_created;
    pmstats.flow_tracker_total_deletes = tmp_stats.memcap_deletes;
    pmstats.flow_tracker_prunes = tmp_stats.memcap_prunes;

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
        char curr_appid_name[40] = {};
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t ip_protocol = 0;
        uint64_t curr_flow_latency = 0;
        uint64_t curr_rule_latency = 0;

        if ( t_constraints->flow_ip_all == true )
        {
            if ( p->flow )
            {
                src_port = p->ptrs.sp;
                dst_port = p->ptrs.dp;

                const AppIdSessionApi* appid_session_api = appid_api.get_appid_session_api(*p->flow);
                if ( appid_session_api )
                {
                    AppId service_id = APP_ID_NONE;
                    appid_session_api->get_app_id(&service_id, nullptr, nullptr, nullptr, nullptr);
                    const char* app_name = appid_api.get_application_name(service_id, *p->flow);
                    if ( app_name  )
                    {
                        strncpy(curr_appid_name, app_name, sizeof(curr_appid_name) - 1);
                        curr_appid_name[sizeof(curr_appid_name) - 1] = '\0';
                    }
                }
                ip_protocol = p->flow->ip_proto;
                curr_flow_latency = p->flow->flowstats.total_flow_latency;
                curr_rule_latency = p->flow->flowstats.total_rule_latency;
            }
        }
        int len = p->pktlen;

        if (p->ptrs.tcph)
            type = SFS_TYPE_TCP;
        else if (p->ptrs.udph)
            type = SFS_TYPE_UDP;

        FlowStateValue* value = find_stats(src_addr, dst_addr, &swapped, curr_appid_name,
            src_port, dst_port, ip_protocol, curr_flow_latency, curr_rule_latency);
        if ( !value )
            return;

        TrafficStats* tmp_stats = &value->traffic_stats[type];

        if ( !swapped )
        {
            tmp_stats->packets_a_to_b++;
            tmp_stats->bytes_a_to_b += len;
        }
        else
        {
            tmp_stats->packets_b_to_a++;
            tmp_stats->bytes_b_to_a += len;
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

        if (cur_stats->appid_name[0] != '\0')
            strncpy(appid_name, cur_stats->appid_name, sizeof(appid_name) - 1);
        else
            strncpy(appid_name, "APPID_NONE", sizeof(appid_name) - 1);
        appid_name[sizeof(appid_name) - 1] = '\0';

        std::snprintf(port_a, sizeof(port_a), "%d", cur_stats->port_a);
        std::snprintf(port_b, sizeof(port_b), "%d", cur_stats->port_b);
        std::snprintf(protocol, sizeof(protocol), "%d", cur_stats->protocol);
        std::snprintf(flow_latency, sizeof(flow_latency), "%lu", cur_stats->total_flow_latency);
        std::snprintf(rule_latency, sizeof(rule_latency), "%lu", cur_stats->total_rule_latency);

        memcpy(&stats, cur_stats, sizeof(stats));

        write();
    }

    if ( !(perf_flags & PERF_SUMMARY) )
        reset();
}

int FlowIPTracker::update_state(const SfIp* src_addr, const SfIp* dst_addr,
    FlowState state, const char* appid_name, uint16_t src_port, uint16_t dst_port,
    uint8_t ip_protocol, uint64_t flow_latency, uint64_t rule_latency)
{
    int swapped;

    FlowStateValue* value = find_stats(src_addr, dst_addr, &swapped, appid_name, src_port, dst_port,
        ip_protocol, flow_latency, rule_latency);
    if ( !value )
        return 1;

    value->state_changes[state]++;
    return 0;
}

