//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include <fstream>
#include <vector>

#include "flow/flow_config.h"
#include "framework/counts.h"
#include "framework/decode_data.h"
#include "framework/inspector.h"
#include "flow/flow_cache.h"

namespace snort
{
class Flow;
class FlowData;
struct FlowKey;
struct Packet;
struct SfIp;
}
class FlowCache;

enum class PruneReason : uint8_t;
enum class FlowDeleteState : uint8_t;

class FlowControl
{
public:
    FlowControl(const FlowCacheConfig& fc);
    ~FlowControl();

    void set_flow_cache_config(const FlowCacheConfig& cfg);
    const FlowCacheConfig& get_flow_cache_config() const;
    void init_proto(PktType, snort::InspectSsnFunc);
    void init_exp(uint32_t max);
    unsigned get_flows_allocated() const;

    bool process(PktType, snort::Packet*, bool* new_flow = nullptr);
    snort::Flow* find_flow(const snort::FlowKey*);
    snort::Flow* new_flow(const snort::FlowKey*);
    void release_flow(const snort::FlowKey*);
    void release_flow(snort::Flow*, PruneReason);
    void purge_flows();
    unsigned delete_flows(unsigned num_to_delete);
    bool prune_one(PruneReason, bool do_cleanup);
    snort::Flow* stale_flow_cleanup(FlowCache*, snort::Flow*, snort::Packet*);
    void timeout_flows(unsigned int, time_t cur_time);
    void check_expected_flow(snort::Flow*, snort::Packet*);
    unsigned prune_multiple(PruneReason, bool do_cleanup);
    bool move_to_allowlist(snort::Flow*);

    bool dump_flows(std::fstream&, unsigned count, const FilterFlowCriteria& ffc, bool first, uint8_t code) const;
    bool dump_flows_summary(FlowsSummary&, const FilterFlowCriteria& ffc) const;


    int add_expected_ignore(
        const snort::Packet* ctrlPkt, PktType, IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        char direction, snort::FlowData*);

    int add_expected(const snort::Packet* ctrlPkt, PktType, IpProtocol, const snort::SfIp *srcIP,
        uint16_t srcPort, const snort::SfIp *dstIP, uint16_t dstPort, SnortProtocolId snort_protocol_id,
        snort::FlowData*, bool swap_app_direction = false, bool expect_multi = false,
        bool bidirectional = false, bool expect_persist = false);

    class ExpectCache* get_exp_cache()
    { return exp_cache; }

    PegCount get_flows()
    { return num_flows; }

    PegCount get_allowlist_flow_count() const;
    PegCount get_excess_to_allowlist_count() const;
    PegCount get_total_prunes() const;
    PegCount get_prunes(PruneReason) const;
    PegCount get_proto_prune_count(PruneReason, PktType) const;
    PegCount get_total_deletes() const;
    PegCount get_deletes(FlowDeleteState state) const;
    void clear_counts();

    PegCount get_uni_flows() const;
    PegCount get_uni_ip_flows() const;
    PegCount get_num_flows() const;

private:
    bool set_key(snort::FlowKey*, snort::Packet*);
    unsigned process(snort::Flow*, snort::Packet*, bool new_ha_flow);
    void update_stats(snort::Flow*, snort::Packet*);

private:
    snort::InspectSsnFunc get_proto_session[to_utype(PktType::MAX)] = {};
    PegCount num_flows = 0;
    FlowCache* cache = nullptr;
    snort::Flow* mem = nullptr;
    class ExpectCache* exp_cache = nullptr;
    PktType last_pkt_type = PktType::NONE;
};

#endif

