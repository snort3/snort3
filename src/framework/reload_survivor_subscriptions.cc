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
// reload_survivor_subscriptions.cc author Bhumika Sachdeva <bsachdev@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reload_survivor_subscriptions.h"
#include "reload_survivor_subscriptions_impl.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "log/messages.h"
#include "main/policy.h"

using namespace snort;

namespace
{

struct HandlerEntry
{
    InspectionPolicy* target_ip;
    const DataBus* bus;
    std::string key;
    DataHandler* handler;
};

struct SurvivorState
{
    std::vector<HandlerEntry> handlers;
    uint64_t np_user_id = 0;
    uint64_t ip_user_id = 0;
    bool ids_initialized = false;

    // guards release() against reconcile_map()
    bool reconciling = false;
};

struct DedupKey
{
    Inspector* survivor;
    InspectionPolicy* target_ip;
    std::string key;

    bool operator==(const DedupKey& o) const
    { return survivor == o.survivor and target_ip == o.target_ip and key == o.key; }
};

struct DedupKeyHash
{
    size_t operator()(const DedupKey& k) const noexcept
    {
        size_t h = std::hash<void*>{}(k.survivor);
        h ^= std::hash<void*>{}(k.target_ip) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(k.key) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        return h;
    }
};

// original (publisher, event) a repeated key is checked against; see classify_dedup()
using DedupEntry = std::pair<const char*, unsigned>;

// in-flight dispatch lease around every RSS handler.
class RssLeaseHandler : public DataHandler
{
public:
    explicit RssLeaseHandler(DataHandler* inner_) :
        DataHandler(inner_->module_name), inner(inner_)
    { order = inner_->order; }

    // waits out any borrow() still held by a drain() outside the registry lock
    ~RssLeaseHandler() override
    {
        while ( borrows.load(std::memory_order_seq_cst) != 0 )
            std::this_thread::yield();
        delete inner;
    }

    // sole owner of inner; non-copyable so a stray value-copy can't double-delete
    RssLeaseHandler(const RssLeaseHandler&) = delete;
    RssLeaseHandler& operator=(const RssLeaseHandler&) = delete;

    // pins this object alive; pair with unborrow() around any use outside the registry lock
    void borrow()
    { borrows.fetch_add(1, std::memory_order_seq_cst); }

    void unborrow()
    { borrows.fetch_sub(1, std::memory_order_seq_cst); }

    void handle(DataEvent& e, Flow* f) override
    {
        inflight.fetch_add(1, std::memory_order_seq_cst);

        if ( live.load(std::memory_order_seq_cst) )
            inner->handle(e, f);
        else
            rss_stats.dead_handler_skips.fetch_add(1, std::memory_order_relaxed);

        inflight.fetch_sub(1, std::memory_order_seq_cst);
    }

    // seq_cst: this live-store pairs with drain()'s inflight-load and handle()'s
    // fetch_add + live-load (store-buffer). inner->live is the wrapped handler's
    // own flag, off that path, so release suffices.
    void retire()
    {
        live.store(false, std::memory_order_seq_cst);
        inner->live.store(false, std::memory_order_release);
    }

    std::atomic<unsigned> inflight { 0 };

private:
    DataHandler* const inner;
    std::atomic<unsigned> borrows { 0 };
};

struct Registry
{
    std::mutex mtx;
    std::unordered_map<Inspector*, SurvivorState> entries;
    std::unordered_map<DedupKey, DedupEntry, DedupKeyHash> dedup;
};

// leaked singleton: registry must outlive every SnortConfig / DataBus at process exit
static Registry& reg()
{
    static Registry* const r = new Registry();
    return *r;
}

// blocks until leased is quiescent; seq_cst pairs with retire() (store-buffer)
static void drain(RssLeaseHandler* leased)
{
    while ( leased->inflight.load(std::memory_order_seq_cst) != 0 )
        std::this_thread::yield();
}

static bool duplicate_subscription(Registry& r, const DedupKey& dk, const PubKey& pub,
    unsigned eid, const char* key)
{
    auto dup = r.dedup.find(dk);
    if ( dup == r.dedup.end() )
        return false;

    if ( classify_dedup(dup->second.first, dup->second.second, pub, eid) == DedupClass::MismatchTuple )
        record_dedup_conflict(key);

    return true;
}

} // namespace

namespace snort
{
RssStats rss_stats;

const PegInfo rss_pegs[] =
{
    { CountType::SUM, "rss_survivors_installed", "successful RSS handler subscribes" },
    { CountType::SUM, "rss_release_retired", "RSS handler subscriptions retired via release()" },
    { CountType::SUM, "rss_bus_destroyed", "on_bus_destroyed() invocations across all bus teardowns" },
    { CountType::SUM, "rss_policy_resolve_fail", "old policy unresolvable in new config on any inspector removal" },
    { CountType::SUM, "rss_list_returned", "total SurvivorView entries returned by list_survivors()" },
    { CountType::SUM, "rss_bus_stripped", "handler entries stripped in on_bus_destroyed()" },
    { CountType::SUM, "rss_dead_pub_skips", "publishes skipped due to dead RSS handler" },
    { CountType::NOW, "rss_survivors_active", "live RSS handler registrations" },
    { CountType::NOW, "rss_registry_tracked", "distinct survivor inspectors tracked in RSS registry" },
    { CountType::SUM, "rss_dedup_conflicts", "subscribe() key reused with a different (publisher, event)" },
    { CountType::END, nullptr, nullptr }
};

static_assert(std::size(rss_pegs) == static_cast<size_t>(RssPeg::Count) + 1,
    "rss_pegs[] must have exactly one entry per RssPeg enumerator, plus the CountType::END sentinel");

void rss_stats_to_pegcounts(const RssStats& stats, PegCount* out)
{
    out[static_cast<size_t>(RssPeg::Installed)] = stats.installed.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::Retired)] = stats.retired.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::BusDestroyed)] = stats.bus_destroyed.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::PolicyResolutionFailures)] =
        stats.policy_resolution_failures.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::ListReturned)] = stats.list_returned.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::Stripped)] = stats.stripped.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::DeadHandlerSkips)] =
        stats.dead_handler_skips.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::Active)] = stats.active.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::RegistryTracked)] =
        stats.registry_tracked.load(std::memory_order_relaxed);
    out[static_cast<size_t>(RssPeg::DedupConflicts)] =
        stats.dedup_conflicts.load(std::memory_order_relaxed);
}

DedupClass classify_dedup(const char* prior_publisher, unsigned prior_eid,
    const PubKey& pub, unsigned eid)
{
    if ( prior_eid != eid or std::strcmp(prior_publisher, pub.publisher) != 0 )
        return DedupClass::MismatchTuple;
    return DedupClass::SameTuple;
}

void record_dedup_conflict(const char* key)
{
    rss_stats.dedup_conflicts.fetch_add(1, std::memory_order_relaxed);
    WarningMessage("RSS: key '%s' reused with a different (publisher, event); "
        "dropping the new subscription\n", key ? key : "");
}
}

ReloadSurvivorSubscriptions::ReloadSurvivorSubscriptions(NetworkPolicy& np_,
    InspectionPolicy& ip_, Inspector& survivor_)
    : np(np_), ip(ip_), survivor(survivor_)
{ }

void ReloadSurvivorSubscriptions::subscribe(const char* key, const PubKey& pub,
    unsigned eid, Factory factory)
{
    DedupKey dk{ &survivor, &ip, key ? key : "" };
    Registry& r = reg();

    // skip the user factory entirely for a duplicate the registry already knows
    {
        std::lock_guard<std::mutex> lock(r.mtx);
        if ( duplicate_subscription(r, dk, pub, eid, key) )
            return;
    }

    // construct outside the lock: factory is user code and may re-enter RSS
    DataHandler* h = factory();

    if ( !h )
        return;

    bool duplicate = false;
    {
        std::lock_guard<std::mutex> lock(r.mtx);

        // factory() may have registered the key re-entrantly; re-check
        if ( duplicate_subscription(r, dk, pub, eid, key) )
            duplicate = true;
        else
        {
            const bool new_entry = (r.entries.find(&survivor) == r.entries.end());
            SurvivorState& state = r.entries[&survivor];

            auto* leased = new RssLeaseHandler(h);

            DataBus::subscribe(ip, pub, eid, leased);

            r.dedup.emplace(dk, DedupEntry{ pub.publisher, eid });

            state.handlers.push_back({ &ip, &ip.dbus, dk.key, leased });

            if ( !state.ids_initialized )
            {
                state.np_user_id = np.user_policy_id;
                state.ip_user_id = ip.user_policy_id;
                state.ids_initialized = true;
            }

            rss_stats.installed.fetch_add(1, std::memory_order_relaxed);
            rss_stats.active.fetch_add(1, std::memory_order_relaxed);
            if ( new_entry )
                rss_stats.registry_tracked.fetch_add(1, std::memory_order_relaxed);
        }
    }

    if ( duplicate )
    {
        // never registered, and user dtors must not run under the registry lock
        delete h;
    }
}

namespace snort
{

bool rss_release(Inspector& survivor)
{
    std::vector<RssLeaseHandler*> to_drain;

    {
        Registry& r = reg();
        std::lock_guard<std::mutex> lock(r.mtx);

        auto it = r.entries.find(&survivor);

        if ( it == r.entries.end() )
            return true;

        if ( it->second.reconciling )
            return false;

        to_drain.reserve(it->second.handlers.size());

        for ( const auto& e : it->second.handlers )
        {
            auto* leased = static_cast<RssLeaseHandler*>(e.handler);
            leased->retire();
            leased->borrow();   // pin alive across the unlocked drain() below
            to_drain.push_back(leased);

            DedupKey dk{ &survivor, e.target_ip, e.key };
            r.dedup.erase(dk);

            rss_stats.retired.fetch_add(1, std::memory_order_relaxed);
            rss_stats.active.fetch_sub(1, std::memory_order_relaxed);
        }

        r.entries.erase(it);
        rss_stats.registry_tracked.fetch_sub(1, std::memory_order_relaxed);
    }   // lock released before drain()

    for ( auto* leased : to_drain )
    {
        drain(leased);
        leased->unborrow();
    }

    return true;
}

bool rss_await_quiescent(Inspector& survivor)
{
    std::vector<RssLeaseHandler*> to_drain;

    {
        Registry& r = reg();
        std::lock_guard<std::mutex> lock(r.mtx);

        auto it = r.entries.find(&survivor);

        if ( it == r.entries.end() )
            return true;

        if ( it->second.reconciling )
            return false;

        to_drain.reserve(it->second.handlers.size());

        for ( const auto& e : it->second.handlers )
        {
            auto* leased = static_cast<RssLeaseHandler*>(e.handler);
            leased->borrow();   // pin alive across the unlocked drain() below
            to_drain.push_back(leased);
        }
    }   // lock released before drain(); no retirement here

    for ( auto* leased : to_drain )
    {
        drain(leased);
        leased->unborrow();
    }

    return true;
}

void rss_on_bus_destroyed(const DataBus* dying_bus)
{
    // defensive: production callers (~DataBus) always pass 'this'; guards test scaffolding
    if ( !dying_bus )
        return;

    rss_stats.bus_destroyed.fetch_add(1, std::memory_order_relaxed);

    Registry& r = reg();
    std::lock_guard<std::mutex> lock(r.mtx);

    // full scan and keep-entry are load-bearing: InspectionPolicy* addresses can be reused
    // after SnortConfig teardown, which would false-hit dedup on next reload
    for ( auto& kv : r.entries )
    {
        Inspector* survivor = kv.first;
        auto& handlers = kv.second.handlers;

        auto new_end = std::remove_if(handlers.begin(), handlers.end(),
            [survivor, dying_bus, &r](const HandlerEntry& e)
            {
                if ( e.bus != dying_bus )
                    return false;
                DedupKey dk{ survivor, e.target_ip, e.key };
                r.dedup.erase(dk);
                rss_stats.stripped.fetch_add(1, std::memory_order_relaxed);
                rss_stats.active.fetch_sub(1, std::memory_order_relaxed);
                return true;
            });

        handlers.erase(new_end, handlers.end());
    }
}

std::vector<RssSurvivorView> rss_list_survivors()
{
    std::vector<RssSurvivorView> out;

    Registry& r = reg();
    std::lock_guard<std::mutex> lock(r.mtx);
    out.reserve(r.entries.size());

    for ( auto& kv : r.entries )
    {
        if ( !kv.second.ids_initialized )
            continue;
        kv.second.reconciling = true;
        out.push_back({ kv.first, kv.second.np_user_id, kv.second.ip_user_id });
    }

    rss_stats.list_returned.fetch_add(out.size(), std::memory_order_relaxed);
    return out;
}

void rss_end_reconcile(Inspector& survivor)
{
    Registry& r = reg();
    std::lock_guard<std::mutex> lock(r.mtx);

    auto it = r.entries.find(&survivor);
    if ( it != r.entries.end() )
        it->second.reconciling = false;
}

void rss_reset_for_test()
{
    Registry& r = reg();
    std::lock_guard<std::mutex> lock(r.mtx);
    r.entries.clear();
    r.dedup.clear();

    rss_stats.active.store(0, std::memory_order_relaxed);
    rss_stats.registry_tracked.store(0, std::memory_order_relaxed);
}

}
