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

// flow_cache.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_CACHE_H
#define FLOW_CACHE_H

// there is a FlowCache instance for each protocol.
// Flows are stored in a ZHash instance by FlowKey.

#include <array>
#include <ctime>
#include <fstream>
#include <mutex>
#include <type_traits>
#include <vector>
#include <memory>

#include "filter_flow_critera.h"
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

typedef std::array<unsigned, to_utype(PktType::MAX)> FlowsTypeSummary;
typedef std::array<unsigned, to_utype(snort::Flow::FlowState::ALLOW) + 1> FlowsStateSummary;

struct FlowsSummary
{
    FlowsTypeSummary type_summary{};
    FlowsStateSummary state_summary{};
};

namespace snort
{
class Flow;
struct FlowKey;
}

class DumpFlowsBase : public snort::AnalyzerCommand
{
public:
    DumpFlowsBase(ControlConn*);
    virtual ~DumpFlowsBase() override= default;
    void cidr2mask(const uint32_t cidr, uint32_t* mask) const;
    bool set_ip(std::string filter_ip, snort::SfIp& ip, snort::SfIp& subnet) const;
    bool execute(Analyzer&, void**) override = 0;
    const char* stringify() override = 0;
    void set_filter_criteria(const FilterFlowCriteria& filter_criteria)
    {ffc = filter_criteria;}

protected:
    FilterFlowCriteria ffc;
};

class DumpFlows : public DumpFlowsBase
{
public:
#ifndef REG_TEST
    DumpFlows(unsigned count, ControlConn*);
#else
    DumpFlows(unsigned count, ControlConn*, int resume);
#endif
    ~DumpFlows() override = default;
    bool open_files(const std::string& base_name);
    bool execute(Analyzer&, void**) override;
    const char* stringify() override
    { return "DumpFlows"; }

private:
    //dump_code is to track if the flow is dumped only once per dump_flow command.
    static uint8_t dump_code;
    std::vector<std::fstream> dump_stream;
    std::vector<unsigned> next;
    unsigned dump_count;
#ifdef REG_TEST
    int resume = -1;
#endif
};

class DumpFlowsSummary : public DumpFlowsBase
{
public:
    DumpFlowsSummary(ControlConn*);

    ~DumpFlowsSummary() override;
    bool execute(Analyzer&, void**) override;
    const char* stringify() override
    { return "DumpFlowsSummary"; }

private:
    std::vector<FlowsSummary> flows_summaries;
};

class FlowUniList;

class FlowCache
{
public:
    FlowCache(const FlowCacheConfig&);
    virtual ~FlowCache();

    FlowCache(const FlowCache&) = delete;
    FlowCache& operator=(const FlowCache&) = delete;

    snort::Flow* find(const snort::FlowKey*);
    snort::Flow* allocate(const snort::FlowKey*);

    bool release(snort::Flow*, PruneReason = PruneReason::NONE, bool do_cleanup = true);

    unsigned prune_idle(time_t thetime, const snort::Flow* save_me);
    unsigned prune_excess(const snort::Flow* save_me);
    bool prune_one(PruneReason, bool do_cleanup, uint8_t type = 0);
    unsigned timeout(unsigned num_flows, time_t cur_time);
    unsigned delete_flows(unsigned num_to_delete);
    unsigned prune_multiple(PruneReason, bool do_cleanup);
    bool dump_flows(std::fstream&, unsigned count, const FilterFlowCriteria& ffc, bool first, uint8_t code) const;
    bool dump_flows_summary(FlowsSummary&, const FilterFlowCriteria& ffc) const;


    unsigned purge();
    unsigned get_count();

    unsigned get_max_flows() const
    { return config.max_flows; }

    PegCount get_total_prunes() const
    { return prune_stats.get_total(); }

    PegCount get_prunes(PruneReason reason) const
    { return prune_stats.get(reason); }

    PegCount get_proto_prune_count(PruneReason reason, PktType type) const
    { return prune_stats.get_proto_prune_count(reason,type); }

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

    bool move_to_allowlist(snort::Flow* f);

    virtual bool filter_flows(const snort::Flow&, const FilterFlowCriteria&) const;
    virtual void output_flow(std::fstream&, const snort::Flow&, const struct timeval&) const;

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
    static std::string timeout_to_str(time_t);
    bool is_ip_match(const snort::SfIp& flow_ip, const snort::SfIp& filter_ip, const snort::SfIp& subnet) const;

    inline bool is_allowlist_on_excess() const
    { return config.allowlist_cache and config.move_to_allowlist_on_excess; }

    inline bool is_lru_checked(uint64_t checked_lrus_mask, uint64_t lru_mask)
    { return (checked_lrus_mask & lru_mask) != 0; }

    inline bool all_lrus_checked(uint64_t checked_lrus_mask)
    { return checked_lrus_mask == all_lru_mask; }

    inline void mark_lru_checked(uint64_t& checked_lrus_mask, uint64_t lru_mask)
    { checked_lrus_mask |= lru_mask; }

    inline uint64_t get_lru_mask(uint8_t lru_idx)
    { return 1ULL << lru_idx; }

    inline void mark_lru_checked(uint64_t& checked_lrus_mask, uint64_t& empty_lru_masks, uint64_t lru_mask)
    {
        checked_lrus_mask |= lru_mask;
        empty_lru_masks |= lru_mask;
    }

private:
    uint8_t timeout_idx;
    static const unsigned cleanup_flows = 1;
    FlowCacheConfig config;
    uint32_t flags;

    class ZHash* hash_table;
    FlowUniList* uni_flows;
    FlowUniList* uni_ip_flows;

    PruneStats prune_stats;
    FlowDeleteStats delete_stats;
    uint64_t empty_lru_mask;
    PegCount excess_to_allowlist_count = 0;

};
#endif

