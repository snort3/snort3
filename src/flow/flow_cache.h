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

// flow_cache.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_CACHE_H
#define FLOW_CACHE_H

// there is a FlowCache instance for each protocol.
// Flows are stored in a ZHash instance by FlowKey.

#include <ctime>
#include <type_traits>

#include "flow_config.h"
#include "prune_stats.h"

namespace snort
{
class Flow;
struct FlowKey;
}

class FlowCache
{
public:
    FlowCache(const FlowConfig&);
    ~FlowCache();

    FlowCache(const FlowCache&) = delete;
    FlowCache& operator=(const FlowCache&) = delete;

    void push(snort::Flow*);

    snort::Flow* find(const snort::FlowKey*);
    snort::Flow* get(const snort::FlowKey*);

    int release(snort::Flow*, PruneReason = PruneReason::NONE, bool do_cleanup = true);

    unsigned prune_unis();
    unsigned prune_stale(uint32_t thetime, const snort::Flow* save_me);
    unsigned prune_excess(const snort::Flow* save_me);
    bool prune_one(PruneReason, bool do_cleanup);
    unsigned timeout(unsigned num_flows, time_t cur_time);

    unsigned purge();
    unsigned get_count();

    unsigned get_max_flows() const
    { return config.max_sessions; }

    PegCount get_total_prunes() const
    { return prune_stats.get_total(); }

    PegCount get_prunes(PruneReason reason) const
    { return prune_stats.get(reason); }

    void reset_stats()
    { prune_stats = PruneStats(); }

    void unlink_uni(snort::Flow*);

private:
    void link_uni(snort::Flow*);
    int remove(snort::Flow*);

private:
    static const unsigned cleanup_flows = 1;
    const FlowConfig config;
    unsigned uni_count;
    uint32_t flags;

    class ZHash* hash_table;
    snort::Flow* uni_head, * uni_tail;
    PruneStats prune_stats;
};

#endif

