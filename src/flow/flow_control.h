//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

class FlowControl
{
public:
    FlowControl();
    ~FlowControl();

public:
    bool process(PktType, snort::Packet*);

    snort::Flow* find_flow(const snort::FlowKey*);
    snort::Flow* new_flow(const snort::FlowKey*);

    void init_proto(PktType, const FlowConfig&, snort::InspectSsnFunc);
    void init_exp(uint32_t max);

    void delete_flow(const snort::FlowKey*);
    void delete_flow(snort::Flow*, PruneReason);
    void purge_flows(PktType);
    bool prune_one(PruneReason, bool do_cleanup);

    void timeout_flows(time_t cur_time);

    bool expected_flow(snort::Flow*, snort::Packet*);
    bool is_expected(snort::Packet*);

    int add_expected(
        const snort::Packet* ctrlPkt, PktType, IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        char direction, snort::FlowData*);

    int add_expected(
        const snort::Packet* ctrlPkt, PktType, IpProtocol,
        const snort::SfIp *srcIP, uint16_t srcPort,
        const snort::SfIp *dstIP, uint16_t dstPort,
        SnortProtocolId snort_protocol_id, snort::FlowData*);

    PegCount get_flows(PktType pt)
    { return proto[to_utype(pt)].num_flows; }

    PegCount get_total_prunes(PktType) const;
    PegCount get_prunes(PktType, PruneReason) const;

    void clear_counts();

private:
    FlowCache* get_cache(PktType pt)
    { return proto[to_utype(pt)].cache; }

    const FlowCache* get_cache(PktType pt) const
    { return proto[to_utype(pt)].cache; }

    void set_key(snort::FlowKey*, snort::Packet*);

    unsigned process(snort::Flow*, snort::Packet*);
    void preemptive_cleanup();

private:
    struct
    {
        FlowCache* cache = nullptr;
        snort::Flow* mem = nullptr;
        snort::InspectSsnFunc get_ssn = nullptr;
        PegCount num_flows = 0;
    } proto[to_utype(PktType::MAX)];

    class ExpectCache* exp_cache = nullptr;
    PktType last_pkt_type = PktType::NONE;

    std::vector<PktType> types;
    unsigned next = 0;
};

#endif

