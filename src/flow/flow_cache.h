//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
#include <fstream>
#include <mutex>
#include <type_traits>
#include <vector>
#include <memory>

#include "framework/counts.h"
#include "flow_config.h"
#include "flow.h"
#include "main/analyzer_command.h"
#include "prune_stats.h"

constexpr uint8_t max_protocols = static_cast<uint8_t>(to_utype(PktType::MAX));
constexpr uint8_t allowlist_lru_index = max_protocols;
constexpr uint8_t total_lru_count = max_protocols + 1;
constexpr uint64_t all_lru_mask = (1ULL << max_protocols) - 1;
constexpr uint8_t first_proto = to_utype(PktType::NONE) + 1;

#ifdef ALLOWLIST_MOVE_ON_EXCESS
constexpr unsigned allowlist_admission_scan_cap = 8;
#endif

namespace snort
{
class Flow;
struct FlowKey;
}

class ZHash;
class FlowUniList;

class FlowCache
{
public:
    FlowCache(const FlowCacheConfig&);
    virtual ~FlowCache();

    FlowCache(const FlowCache&) = delete;
    FlowCache& operator=(const FlowCache&) = delete;

    ZHash* get_flow_table() const
    { return hash_table; }

    snort::Flow* find(const snort::FlowKey*);
    snort::Flow* allocate(const snort::FlowKey*);

    bool release(snort::Flow*, PruneReason = PruneReason::NONE, bool do_cleanup = true);

    unsigned prune_idle(time_t thetime, const snort::Flow* save_me);
    unsigned prune_excess(const snort::Flow* save_me);
    bool prune_one(PruneReason, bool do_cleanup, uint8_t type = 0);
    unsigned timeout(unsigned num_flows, time_t cur_time);
    unsigned delete_flows(unsigned num_to_delete);
    unsigned prune_multiple(PruneReason, bool do_cleanup);

    unsigned purge();
    unsigned get_count();

    // cppcheck-suppress unusedFunction ; entry point retained for external, conditional, or test use
    unsigned get_max_flows() const
    { return config.max_flows; }

    // cppcheck-suppress unusedFunction ; entry point retained for external, conditional, or test use
    PegCount get_total_prunes() const
    { return prune_stats.get_total(); }

    PegCount get_prunes(PruneReason reason) const
    { return prune_stats.get(reason); }

    PegCount get_proto_prune_count(PruneReason reason, PktType type) const
    { return prune_stats.get_proto_prune_count(reason,type); }

    // cppcheck-suppress unusedFunction ; entry point retained for external, conditional, or test use
    PegCount get_total_deletes() const
    { return delete_stats.get_total(); }

    // cppcheck-suppress unusedFunction ; entry point retained for external, conditional, or test use
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

    bool move_to_allowlist(snort::Flow* f);

    void allowlist_on_excess_check(time_t now);

    template<typename StreamType>
    void output_flow(StreamType&, const snort::Flow&, const struct timeval&) const;

    unsigned get_flows_allocated() const;
    size_t uni_flows_size() const;
    size_t uni_ip_flows_size() const;
    size_t flows_size() const;
    PegCount get_lru_flow_count(uint8_t lru_idx) const;
    PegCount get_excess_to_allowlist_count() const
    { return excess_to_allowlist_count; }
#ifdef UNIT_TEST
    size_t count_flows_in_lru(uint8_t lru_index) const;
#endif

private:
    void delete_uni();
    void push(snort::Flow*);
    void link_uni(snort::Flow*);
    void remove(snort::Flow*);
    void retire(snort::Flow*);
    unsigned prune_unis(PktType);
    bool allowlist_on_excess(snort::Flow*);
    bool handle_allowlist_pruning(snort::Flow*, PruneReason, uint8_t, bool&);

    unsigned delete_active_flows(unsigned mode, unsigned num_to_delete, unsigned &deleted);

    inline bool is_allowlist_on_excess() const
    {
#ifdef ALLOWLIST_MOVE_ON_EXCESS
        return config.allowlist_cache and config.move_to_allowlist_on_excess
            and config.allowlist_max_excess_flows > 0
            and config.allowlist_max_excess_flows < config.max_flows;
#else
        return false;
#endif
    }

    static inline bool is_lru_checked(uint64_t checked_lrus_mask, uint64_t lru_mask)
    { return (checked_lrus_mask & lru_mask) != 0; }

    static inline bool all_lrus_checked(uint64_t checked_lrus_mask)
    { return checked_lrus_mask == all_lru_mask; }

    static inline void mark_lru_checked(uint64_t& checked_lrus_mask, uint64_t lru_mask)
    { checked_lrus_mask |= lru_mask; }

    static inline uint64_t get_lru_mask(uint8_t lru_idx)
    { return 1ULL << lru_idx; }

    static inline void mark_lru_checked(uint64_t& checked_lrus_mask, uint64_t& empty_lru_masks,
        uint64_t lru_mask)
    {
        checked_lrus_mask |= lru_mask;
        empty_lru_masks |= lru_mask;
    }

    inline void log_flow_release(const snort::Flow* flow, PruneReason reason) const;

private:
    uint8_t timeout_idx = 0;
    static const unsigned cleanup_flows = 1;
    FlowCacheConfig config;
    uint32_t flags = 0;

    ZHash* hash_table = nullptr;
    FlowUniList* uni_flows = nullptr;
    FlowUniList* uni_ip_flows = nullptr;

    PruneStats prune_stats;
    FlowDeleteStats delete_stats;
    uint64_t empty_lru_mask = 0;
    PegCount excess_to_allowlist_count = 0;

};
#endif
