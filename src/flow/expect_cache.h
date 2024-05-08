//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

// expect_cache.h author Russ Combs <rucombs@cisco.com>

#ifndef EXPECT_CACHE_H
#define EXPECT_CACHE_H

// ExpectCache is used to track anticipated flows (like ftp data channels).
// when the flow is found, it updated with the given info.

#include "flow/flow_key.h"
#include "target_based/snort_protocols.h"

struct ExpectNode;

namespace snort
{
class Flow;
class FlowData;

struct ExpectFlow;
struct Packet;
}

class ExpectCache
{
public:
    ExpectCache(uint32_t max);
    ~ExpectCache();

    ExpectCache(const ExpectCache&) = delete;
    ExpectCache& operator=(const ExpectCache&) = delete;

    int add_flow(const snort::Packet *ctrlPkt, PktType, IpProtocol, const snort::SfIp* cliIP,
        uint16_t cliPort, const snort::SfIp* srvIP, uint16_t srvPort, char direction,
        snort::FlowData*, SnortProtocolId snort_protocol_id = UNKNOWN_PROTOCOL_ID,
        bool swap_app_direction = false, bool expect_multi = false, bool bidirectional = false,
        bool expect_persist = false);

    bool check(snort::Packet*, snort::Flow*);

    unsigned long get_expects() { return expects; }
    unsigned long get_realized() { return realized; }
    unsigned long get_prunes() { return prunes; }
    unsigned long get_overflows() { return overflows; }
    void reset_stats()
    {
        expects = 0;
        realized = 0;
        prunes = 0;
        overflows = 0;
    }

private:
    void prune_lru();

    ExpectNode* get_node(snort::FlowKey&, bool&);
    snort::ExpectFlow* get_flow(ExpectNode*, uint32_t, int16_t);
    bool set_data(ExpectNode*, snort::ExpectFlow*&, snort::FlowData*);
    ExpectNode* find_node_by_packet(snort::Packet*, snort::FlowKey&);
    bool process_expected(ExpectNode*, snort::FlowKey&, snort::Packet*, snort::Flow*);

private:
    class ZHash* hash_table;
    ExpectNode* nodes;
    snort::ExpectFlow* pool;
    snort::ExpectFlow* free_list;

    unsigned long expects = 0;
    unsigned long realized = 0;
    unsigned long prunes = 0;
    unsigned long overflows = 0;
};

#endif

