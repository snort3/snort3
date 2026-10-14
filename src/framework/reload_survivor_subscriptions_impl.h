//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// reload_survivor_subscriptions_impl.h author Bhumika Sachdeva <bsachdev@cisco.com>

// Framework-internal RSS surface: lifecycle entry points, pegs and the
// survivor flow-data pin.  Not installed, so none of this is plugin-visible.

#ifndef RELOAD_SURVIVOR_SUBSCRIPTIONS_IMPL_H
#define RELOAD_SURVIVOR_SUBSCRIPTIONS_IMPL_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "flow/flow_data.h"
#include "framework/counts.h"
#include "main/snort_types.h"

namespace snort
{
class DataBus;
class Inspector;
struct PubKey;

// order must match RssStats and rss_pegs[] exactly
enum class RssPeg : size_t
{
    Installed,
    Retired,
    BusDestroyed,
    PolicyResolutionFailures,
    ListReturned,
    Stripped,
    DeadHandlerSkips,
    Active,
    RegistryTracked,
    DedupConflicts,
    SlowDrains,
    ReconcileDeferrals,
    Count
};

// atomic, not thread-local: written from both main and packet threads
struct RssStats
{
    std::atomic<PegCount> installed{0};
    std::atomic<PegCount> retired{0};
    std::atomic<PegCount> bus_destroyed{0};
    std::atomic<PegCount> policy_resolution_failures{0};
    std::atomic<PegCount> list_returned{0};
    std::atomic<PegCount> stripped{0};
    std::atomic<PegCount> dead_handler_skips{0};
    std::atomic<PegCount> active{0};
    std::atomic<PegCount> registry_tracked{0};
    std::atomic<PegCount> dedup_conflicts{0};
    std::atomic<PegCount> slow_drains{0};
    std::atomic<PegCount> reconcile_deferrals{0};

    void reset()
    {
        installed.store(0, std::memory_order_relaxed);
        retired.store(0, std::memory_order_relaxed);
        bus_destroyed.store(0, std::memory_order_relaxed);
        policy_resolution_failures.store(0, std::memory_order_relaxed);
        list_returned.store(0, std::memory_order_relaxed);
        stripped.store(0, std::memory_order_relaxed);
        dead_handler_skips.store(0, std::memory_order_relaxed);
        dedup_conflicts.store(0, std::memory_order_relaxed);
        slow_drains.store(0, std::memory_order_relaxed);
        reconcile_deferrals.store(0, std::memory_order_relaxed);
    }
};

extern RssStats rss_stats;
extern const PegInfo rss_pegs[];

// out must have at least RssPeg::Count elements
void rss_stats_to_pegcounts(const RssStats& stats, PegCount* out);

enum class DedupClass
{
    SameTuple,
    MismatchTuple
};

DedupClass classify_dedup(const char* prior_publisher, unsigned prior_eid,
    const PubKey& pub, unsigned eid);

void record_dedup_conflict(const char* key);

// one row per survivor inspector tracked in the registry
struct RssSurvivorView
{
    Inspector* survivor;
    uint64_t np_user_id;
    uint64_t ip_user_id;
};

// returns false if reconcile_map() still owns this survivor
bool rss_release(Inspector& survivor);

// Drain callbacks already executing for this survivor without retiring
// its subscriptions; this does not stop later dispatch.
bool rss_await_quiescent(Inspector& survivor);

void rss_on_bus_destroyed(const DataBus* dying_bus);

std::vector<RssSurvivorView> rss_list_survivors(unsigned reload_id);

// must be called exactly once for every entry rss_list_survivors(reload_id) returns,
// or that survivor's teardown stalls forever.
void rss_end_reconcile(Inspector& survivor);

void rss_reset_for_test();

#ifdef UNIT_TEST
void rss_set_elapsed_for_test(uint64_t ms);
#endif

// pins a survivor Inspector alive across mid-flow gadget rebinds.
class SurvivorFlowData : public FlowData
{
public:
    explicit SurvivorFlowData(Inspector* pin);
    ~SurvivorFlowData() override;

    // idempotent: adding an already-held pin is a no-op
    void add_pin(Inspector* pin);

    static unsigned get_flow_data_id() { return flow_data_id; }

private:
    std::vector<Inspector*> pinned;
    static unsigned flow_data_id;
};

}

#endif
