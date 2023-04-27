//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/counts.h"
#include "main/thread.h"

#include "flow_config.h"
#include "prune_stats.h"

namespace snort
{
class Flow;
struct FlowKey;
}

class FlowUniList;

class FlowCache
{
public:
    FlowCache(const FlowCacheConfig&);
    ~FlowCache();

    FlowCache(const FlowCache&) = delete;
    FlowCache& operator=(const FlowCache&) = delete;

    snort::Flow* find(const snort::FlowKey*);
    snort::Flow* allocate(const snort::FlowKey*);

    bool release(snort::Flow*, PruneReason = PruneReason::NONE, bool do_cleanup = true);

    unsigned prune_stale(uint32_t thetime, const snort::Flow* save_me);
    unsigned prune_excess(const snort::Flow* save_me);
    bool prune_one(PruneReason, bool do_cleanup);
    unsigned timeout(unsigned num_flows, time_t cur_time);
    unsigned delete_flows(unsigned num_to_delete);
    unsigned prune_multiple(PruneReason, bool do_cleanup);

    unsigned purge();
    unsigned get_count();

    unsigned get_max_flows() const
    { return config.max_flows; }

    PegCount get_total_prunes() const
    { return prune_stats.get_total(); }

    PegCount get_prunes(PruneReason reason) const
    { return prune_stats.get(reason); }

    PegCount get_total_deletes() const
    { return delete_stats.get_total(); }

    PegCount get_deletes(FlowDeleteState state) const
    { return delete_stats.get(state); }

    void reset_stats()
    {
        prune_stats = PruneStats();
        delete_stats = FlowDeleteStats();
    }

    void unlink_uni(snort::Flow*);

    void set_flow_cache_config(const FlowCacheConfig& cfg)
    { config = cfg; }

    const FlowCacheConfig& get_flow_cache_config() const
    { return config; }

    unsigned get_flows_allocated() const
    { return flows_allocated; }

    static bool is_pruning_in_progress()
    { return pruning_in_progress; }

    size_t uni_flows_size() const;
    size_t uni_ip_flows_size() const;
    size_t flows_size() const;
    size_t free_flows_size() const;

private:
    void delete_uni();
    void push(snort::Flow*);
    void link_uni(snort::Flow*);
    void remove(snort::Flow*);
    void retire(snort::Flow*);
    unsigned prune_unis(PktType);
    unsigned delete_active_flows
        (unsigned mode, unsigned num_to_delete, unsigned &deleted);

private:
    static THREAD_LOCAL bool pruning_in_progress;
    static const unsigned cleanup_flows = 1;
    FlowCacheConfig config;
    uint32_t flags;

    class ZHash* hash_table;
    unsigned flows_allocated = 0;
    FlowUniList* uni_flows;
    FlowUniList* uni_ip_flows;

    PruneStats prune_stats;
    FlowDeleteStats delete_stats;
};
#endif

