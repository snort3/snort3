//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// flow_cache.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_CACHE_H
#define FLOW_CACHE_H

// there is a FlowCache instance for each protocol.
// Flows are stored in a ZHash instance by FlowKey.

#include <ctime>
#include <type_traits>

#include "flow/flow_config.h"
#include "flow/memcap.h"

class Flow;
struct FlowKey;

// FIXIT-L J we can probably fiddle with these breakdowns
enum class PruneReason : uint8_t
{
    PURGE = 0,
    TIMEOUT,
    EXCESS,
    UNI,
    HA_SYNC,
    CLOSED,
    USER,
    MAX
};

struct PruneStats
{
    using reason_t = std::underlying_type<PruneReason>::type;

    uint32_t prunes[static_cast<reason_t>(PruneReason::MAX)] { };

    uint64_t get_total() const;
    void update(PruneReason reason)
    { ++prunes[static_cast<reason_t>(reason)]; }
};

class FlowCache
{
public:
    FlowCache(
        const FlowConfig&,
        uint32_t cleanup_flows,
        uint32_t cleanup_percent);

    ~FlowCache();

    void push(Flow*);

    Flow* find(const FlowKey*);
    Flow* get(const FlowKey*);

    int release(Flow*, PruneReason = PruneReason::USER);

    uint32_t prune_unis();
    uint32_t prune_stale(uint32_t thetime, const Flow* save_me);
    uint32_t prune_excess(const Flow* save_me);
    bool prune_one(PruneReason);
    void timeout(uint32_t num_flows, time_t cur_time);

    int purge();
    int get_count();

    uint32_t get_max_flows() const
    { return config.max_sessions; }

    uint64_t get_prunes() const
    { return prune_stats.get_total(); }

    void reset_prunes()
    { prune_stats = PruneStats(); }

    void unlink_uni(Flow*);

    Memcap& get_memcap() { return memcap; }

private:
    void link_uni(Flow*);
    int remove(Flow*);

private:
    const FlowConfig& config;
    uint32_t cleanup_flows;
    uint32_t uni_count;
    uint32_t flags;

    Memcap memcap;

    class ZHash* hash_table;
    Flow* uni_head, * uni_tail;
    PruneStats prune_stats;
};

#endif

