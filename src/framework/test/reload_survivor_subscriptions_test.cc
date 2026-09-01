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
// reload_survivor_subscriptions_test.cc author Bhumika Sachdeva <bsachdev@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/reload_survivor_subscriptions.h"
#include "framework/reload_survivor_subscriptions_impl.h"

#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "main/policy.h"
#include "main/snort_config.h"
#include "utils/stats.h"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

//--------------------------------------------------------------------------
// mocks (mirror data_bus_test.cc)
//--------------------------------------------------------------------------
InspectionPolicy::InspectionPolicy(unsigned int) : service_group(nullptr) {}
InspectionPolicy::~InspectionPolicy() = default;
NetworkPolicy::NetworkPolicy(unsigned int, unsigned int) : file_policy(nullptr) {}
NetworkPolicy::~NetworkPolicy() = default;

// RSS uses Inspector* only as an opaque key, so this stub can be empty --
// except the dtor, which must call release() to mirror the real
// ~Inspector() for tests exercising zero-flow-ref teardown.
// Non-inline virtuals below just need to resolve at link time (vtable).
Inspector::Inspector() : ref_count(nullptr) {}
Inspector::~Inspector() { rss_release(*this); }
bool Inspector::likes(Packet*) { return true; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }

namespace snort
{

static SnortConfig s_conf;

THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

SnortConfig::SnortConfig(const char*)
{ global_dbus = new DataBus(); }

SnortConfig::~SnortConfig()
{ delete global_dbus; }

NetworkPolicy* get_network_policy()
{
    return (NetworkPolicy*)mock().getData("my_network_policy").getObjectPointer();
}

InspectionPolicy* get_inspection_policy()
{
    return (InspectionPolicy*)mock().getData("my_inspection_policy").getObjectPointer();
}

void set_network_policy(NetworkPolicy*) { }
void set_inspection_policy(InspectionPolicy*) { }

void WarningMessage(const char* format, ...)
{ mock().actualCall("WarningMessage").withParameter("format", format); }

THREAD_LOCAL PacketCount pc;
}

//--------------------------------------------------------------------------
// helpers
//--------------------------------------------------------------------------
namespace
{

class CountingEvent : public DataEvent
{
public:
    CountingEvent() = default;
};

class CountingHandler : public DataHandler
{
public:
    CountingHandler() : DataHandler("rss_ut") { }

    void handle(DataEvent&, Flow*) override
    { calls.fetch_add(1, std::memory_order_relaxed); }

    std::atomic<unsigned> calls { 0 };
};

// counts into a caller-owned atomic instead of a member, so the count is
// still readable after this handler itself has been deleted (e.g. a
// rejected dedup-conflict subscription).
class ExternalCountHandler : public DataHandler
{
public:
    explicit ExternalCountHandler(std::atomic<unsigned>& counter_) :
        DataHandler("rss_ut"), counter(counter_) { }

    void handle(DataEvent&, Flow*) override
    { counter.fetch_add(1, std::memory_order_relaxed); }

private:
    std::atomic<unsigned>& counter;
};

// widens the in-flight window for release() to race against
class SlowHandler : public DataHandler
{
public:
    SlowHandler(std::atomic<bool>& entered_, std::atomic<bool>& done_,
        unsigned delay_ms = 50) :
        DataHandler("rss_ut_slow"), entered(entered_), done(done_), delay_ms(delay_ms) { }

    void handle(DataEvent&, Flow*) override
    {
        entered.store(true, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        done.store(true, std::memory_order_release);
    }

private:
    std::atomic<bool>& entered;
    std::atomic<bool>& done;
    unsigned delay_ms;
};

// Minimal concrete Inspector: pure-virtual-free; RSS only takes its
// address as a key.
class FakeInspector : public Inspector
{
public:
    FakeInspector() : Inspector() { }
};

// deliberately plain (not atomic) so a real TSAN race can fire on it
class RacingInspector : public Inspector
{
public:
    RacingInspector() : Inspector() { }
    int state = 0;
};

struct RssUtIds { enum : unsigned { EVENT, EVENT_OTHER, num_ids }; };

const PubKey rss_pub_key { "rss_ut", RssUtIds::num_ids };
const PubKey rss_pub_key_other { "rss_ut_other", RssUtIds::num_ids };

} // namespace

//--------------------------------------------------------------------------
// reload survivor subscription tests
//--------------------------------------------------------------------------

TEST_GROUP(reload_survivor_subscriptions)
{
    InspectionPolicy my_inspection_policy;
    NetworkPolicy my_network_policy;
    unsigned pub_id = 0;

    void setup() override
    {
        // Populate ids that subscribe() snapshots into the registry
        // entry; list_survivors() and the multi-reload reattach tests
        // verify these come back unchanged.
        my_network_policy.user_policy_id = 42;
        my_inspection_policy.user_policy_id = 7;

        mock().setDataObject("my_network_policy", "NetworkPolicy", &my_network_policy);
        mock().setDataObject("my_inspection_policy", "InspectionPolicy", &my_inspection_policy);

        pub_id = DataBus::get_id(rss_pub_key);
        CHECK_TRUE(DataBus::valid(pub_id));

        rss_reset_for_test();
        rss_stats.reset();
    }

    void teardown() override
    {
        rss_reset_for_test();
        mock().clear();
    }
};

// Subscribed survivor handler receives published events.
TEST(reload_survivor_subscriptions, subscribe_and_publish)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* h = new CountingHandler();
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [h]() -> DataHandler* { return h; });

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, h->calls);

    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(2u, h->calls);
}

// release() flips live -> false; _publish skips the dead handler.
TEST(reload_survivor_subscriptions, release_marks_handler_dead)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* h = new CountingHandler();
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [h]() -> DataHandler* { return h; });

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, h->calls);
    CHECK_TRUE(h->live.load());

    rss_release(survivor);
    CHECK_FALSE(h->live.load());

    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, h->calls);  // no new dispatch
}

// await_quiescent() drains inflight but must NOT retire the handler; a
// subsequent publish still lands.  It is an in-flight drain, not a gate
// against future dispatch, and must be side-effect-free w.r.t. live.
TEST(reload_survivor_subscriptions, await_quiescent_drains_without_retiring)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* h = new CountingHandler();
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [h]() -> DataHandler* { return h; });

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, h->calls);
    CHECK_TRUE(h->live.load());

    CHECK_TRUE(rss_await_quiescent(survivor));
    CHECK_TRUE(h->live.load());  // NOT retired

    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(2u, h->calls);   // still fires
}

// await_quiescent() must block on an in-flight handle() just like release(),
// so a packet thread cannot proceed to tterm() while another thread is
// still inside the handler.
TEST(reload_survivor_subscriptions, await_quiescent_waits_for_inflight_handle)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    std::atomic<bool> entered{false};
    std::atomic<bool> handled_done{false};

    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [&]() -> DataHandler*
        { return new SlowHandler(entered, handled_done); });

    std::thread publisher([&]()
    {
        CountingEvent e;
        DataBus::publish(pub_id, RssUtIds::EVENT, e);
    });

    while ( !entered.load(std::memory_order_acquire) )
        std::this_thread::yield();

    CHECK_TRUE(rss_await_quiescent(survivor));
    CHECK_TRUE(handled_done.load(std::memory_order_acquire));

    publisher.join();
}

// release() blocks on an in-flight handle(); see dev_notes.txt.
TEST(reload_survivor_subscriptions, release_waits_for_inflight_handle)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    std::atomic<bool> entered{false};
    std::atomic<bool> handled_done{false};

    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [&]() -> DataHandler*
        { return new SlowHandler(entered, handled_done); });

    std::thread publisher([&]()
    {
        CountingEvent e;
        DataBus::publish(pub_id, RssUtIds::EVENT, e);
    });

    while ( !entered.load(std::memory_order_acquire) )
        std::this_thread::yield();

    rss_release(survivor);
    CHECK_TRUE(handled_done.load(std::memory_order_acquire));

    publisher.join();
}

// release() must drain every handler on a survivor, not just the first
// one collected -- two handlers, staggered delays so a release() that
// only waited for the shorter one would fail the second check.
TEST(reload_survivor_subscriptions, release_waits_for_all_inflight_handles)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    std::atomic<bool> entered_a{false}, done_a{false};
    std::atomic<bool> entered_b{false}, done_b{false};

    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [&]() -> DataHandler*
        { return new SlowHandler(entered_a, done_a); });
    rss.subscribe("k2", rss_pub_key, RssUtIds::EVENT_OTHER, [&]() -> DataHandler*
        { return new SlowHandler(entered_b, done_b, 150); });

    CountingEvent e;
    std::thread publisher_a([&]()
    { DataBus::publish(pub_id, RssUtIds::EVENT, e); });
    std::thread publisher_b([&]()
    { DataBus::publish(pub_id, RssUtIds::EVENT_OTHER, e); });

    while ( !entered_a.load(std::memory_order_acquire) or
            !entered_b.load(std::memory_order_acquire) )
        std::this_thread::yield();

    rss_release(survivor);
    CHECK_TRUE(done_a.load(std::memory_order_acquire));
    CHECK_TRUE(done_b.load(std::memory_order_acquire));

    publisher_a.join();
    publisher_b.join();
}

// Same (survivor, target ip, key) tuple subscribed twice: a known duplicate
// is rejected before invoking the user factory, so only the first handler
// remains registered on the bus and only one dispatch occurs.
TEST(reload_survivor_subscriptions, dedup_same_tuple)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    unsigned factory_calls = 0;
    CountingHandler* first = new CountingHandler();

    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
        [&]() -> DataHandler*
        {
            ++factory_calls;
            return first;
        });

    // Second subscribe with the same tuple.  RSS detects the duplicate
    // before invoking the factory.
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
        [&]() -> DataHandler*
        {
            ++factory_calls;
            return new CountingHandler();
        });

    CHECK_EQUAL(1u, factory_calls);

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, first->calls);  // only first handler registered
}

// A re-entrant subscribe can win the key after the outer call's early
// dedup check but before its factory returns.  The second check must reject
// the outer handler and must do so without holding the registry mutex while
// running either factory.
TEST(reload_survivor_subscriptions, dedup_rechecks_after_reentrant_factory)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    unsigned factory_calls = 0;
    CountingHandler* registered = new CountingHandler();

    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
        [&]() -> DataHandler*
        {
            ++factory_calls;
            rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
                [&]() -> DataHandler*
                {
                    ++factory_calls;
                    return registered;
                });
            return new CountingHandler();
        });

    CHECK_EQUAL(2u, factory_calls);

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, registered->calls);  // only the re-entrant handler remains
}

// classify_dedup() is the pure predicate subscribe() consults on a dedup
// hit.  All three ways a reused key's (publisher, event) can diverge from
// the original subscription must be flagged, so a future misuse of a key
// (e.g. copy-pasted subscribe() call, stale key after a rename) is
// diagnosed rather than silently treated as the same subscription.
TEST(reload_survivor_subscriptions, classify_dedup_mismatch_when_pub_or_eid_differs)
{
    CHECK_EQUAL((int)DedupClass::MismatchTuple,
        (int)classify_dedup(rss_pub_key.publisher, RssUtIds::EVENT,
            rss_pub_key_other, RssUtIds::EVENT));

    CHECK_EQUAL((int)DedupClass::MismatchTuple,
        (int)classify_dedup(rss_pub_key.publisher, RssUtIds::EVENT,
            rss_pub_key, RssUtIds::EVENT_OTHER));

    CHECK_EQUAL((int)DedupClass::MismatchTuple,
        (int)classify_dedup(rss_pub_key.publisher, RssUtIds::EVENT,
            rss_pub_key_other, RssUtIds::EVENT_OTHER));

    CHECK_EQUAL((int)DedupClass::SameTuple,
        (int)classify_dedup(rss_pub_key.publisher, RssUtIds::EVENT,
            rss_pub_key, RssUtIds::EVENT));
}

// record_dedup_conflict() is the diagnostic subscribe() calls on a
// mismatched-tuple dedup hit: it must bump the peg and warn.
TEST(reload_survivor_subscriptions, record_dedup_conflict_bumps_peg_and_warns)
{
    mock().expectOneCall("WarningMessage").ignoreOtherParameters();

    CHECK_EQUAL(0u, rss_stats.dedup_conflicts.load());
    record_dedup_conflict("k1");
    CHECK_EQUAL(1u, rss_stats.dedup_conflicts.load());

    mock().checkExpectations();
}

// subscribe() explicitly normalizes a null key to "" for DedupKey, but the
// mismatch branch forwarded the raw (possibly null) key straight into
// WarningMessage's %s -- a null format arg is undefined behavior. Confirms
// the null case is now handled the same as any other key.
TEST(reload_survivor_subscriptions, record_dedup_conflict_handles_null_key)
{
    mock().expectOneCall("WarningMessage").ignoreOtherParameters();

    CHECK_EQUAL(0u, rss_stats.dedup_conflicts.load());
    record_dedup_conflict(nullptr);
    CHECK_EQUAL(1u, rss_stats.dedup_conflicts.load());

    mock().checkExpectations();
}

// A direct subscribe() call (not classify_dedup() in isolation) must reach
// the mismatch branch, reject the new subscription, and leave the original
// one intact and working.
TEST(reload_survivor_subscriptions, subscribe_diagnoses_mismatch)
{
    mock().expectOneCall("WarningMessage").ignoreOtherParameters();

    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* first = new CountingHandler();
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
        [first]() -> DataHandler* { return first; });

    // same key, different eid -- must be diagnosed and rejected, not silently dropped
    std::atomic<unsigned> conflict_calls{0};
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT_OTHER,
        [&conflict_calls]() -> DataHandler*
        { return new ExternalCountHandler(conflict_calls); });

    CHECK_EQUAL(1u, rss_stats.dedup_conflicts.load());

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, first->calls.load());       // original subscription still works

    DataBus::publish(pub_id, RssUtIds::EVENT_OTHER, e);
    CHECK_EQUAL(0u, conflict_calls.load());     // rejected handler was never registered

    mock().checkExpectations();
}

// Different keys for the same survivor get separate handlers.
TEST(reload_survivor_subscriptions, distinct_keys_distinct_handlers)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* h1 = new CountingHandler();
    CountingHandler* h2 = new CountingHandler();

    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [h1]() -> DataHandler* { return h1; });
    rss.subscribe("k2", rss_pub_key, RssUtIds::EVENT, [h2]() -> DataHandler* { return h2; });

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, h1->calls);
    CHECK_EQUAL(1u, h2->calls);
}

// Releasing one survivor must not flip another survivor's handlers.
TEST(reload_survivor_subscriptions, release_isolation_between_survivors)
{
    FakeInspector survivor_a;
    FakeInspector survivor_b;

    ReloadSurvivorSubscriptions rss_a(my_network_policy, my_inspection_policy, survivor_a);
    ReloadSurvivorSubscriptions rss_b(my_network_policy, my_inspection_policy, survivor_b);

    CountingHandler* h_a = new CountingHandler();
    CountingHandler* h_b = new CountingHandler();

    rss_a.subscribe("k", rss_pub_key, RssUtIds::EVENT, [h_a]() -> DataHandler* { return h_a; });
    rss_b.subscribe("k", rss_pub_key, RssUtIds::EVENT, [h_b]() -> DataHandler* { return h_b; });

    rss_release(survivor_a);

    CHECK_FALSE(h_a->live.load());
    CHECK_TRUE(h_b->live.load());

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(0u, h_a->calls);
    CHECK_EQUAL(1u, h_b->calls);
}

// release() on a survivor that has nothing registered is a no-op.
TEST(reload_survivor_subscriptions, release_unknown_survivor_is_noop)
{
    FakeInspector survivor;
    // No subscribe.  Must not crash, must not assert.
    rss_release(survivor);
}

// A survivor destroyed with zero flow refs never reaches
// finish_pending_tterm(), so RSS::release() is not called via that path.
// Inspector::~Inspector() calls it directly instead -- this proves that
// path retires the registry entry and the handler before the memory is
// freed, so a later publish cannot dereference the dead survivor.
TEST(reload_survivor_subscriptions, zero_flow_destroy_releases_before_free)
{
    auto* survivor = new FakeInspector();
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, *survivor);

    CountingHandler* h = new CountingHandler();
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [h]() -> DataHandler* { return h; });

    auto snap = rss_list_survivors();
    CHECK_EQUAL(1u, snap.size());
    rss_end_reconcile(*survivor);

    delete survivor;

    CHECK_EQUAL(0u, rss_list_survivors().size());
    CHECK_FALSE(h->live.load());

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(0u, h->calls);
}

// ~DataBus() must call on_bus_destroyed and strip the registry's
// handler entries that point at the dying bus.  The registry entry
// itself is retained (ids snapshot preserved for multi-reload), but
// its handler list becomes empty so a subsequent release() does NOT
// dereference the freed handler memory.
TEST(reload_survivor_subscriptions, bus_destroyed_strips_handlers_keeps_entry)
{
    FakeInspector survivor;

    // Heap-allocate ip so we can destroy it explicitly mid-test.
    auto* ip = new InspectionPolicy();
    ip->user_policy_id = 7;

    {
        ReloadSurvivorSubscriptions rss(my_network_policy, *ip, survivor);
        // Handler is owned by ip->dbus and will be freed by ~DataBus.
        rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }

    // Registry entry exists with snapshotted ids.
    auto pre = rss_list_survivors();
    CHECK_EQUAL(1u, pre.size());
    POINTERS_EQUAL(&survivor, pre[0].survivor);
    rss_end_reconcile(survivor);

    // Tear down the policy / its DataBus.  This triggers
    // ~DataBus -> rss_on_bus_destroyed(this),
    // which strips the registry's handler entry that referenced the
    // dying bus before the handler is freed.  The registry entry for
    // this survivor is RETAINED so its ids snapshot survives across
    // the reload (this is what multi-reload reattach relies on).
    delete ip;

    // Entry still present.
    auto post = rss_list_survivors();
    CHECK_EQUAL(1u, post.size());
    POINTERS_EQUAL(&survivor, post[0].survivor);
    CHECK_EQUAL(42u, post[0].np_user_id);
    CHECK_EQUAL(7u, post[0].ip_user_id);
    rss_end_reconcile(survivor);

    // release() must be safe: handler list is empty so no dereference
    // of the freed handler occurs.  Entry is erased after this call.
    rss_release(survivor);

    auto after_release = rss_list_survivors();
    CHECK_EQUAL(0u, after_release.size());
}

// After bus destruction the same (survivor, key) tuple can be
// re-registered on a fresh policy — dedup must not block it.
TEST(reload_survivor_subscriptions, resubscribe_after_bus_destroyed)
{
    FakeInspector survivor;

    auto* ip1 = new InspectionPolicy();
    ip1->user_policy_id = 7;
    {
        ReloadSurvivorSubscriptions rss(my_network_policy, *ip1, survivor);
        rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }
    delete ip1;

    // Fresh policy, fresh bus, same survivor + key.  Dedup must allow
    // this because on_bus_destroyed cleared the dedup entry.
    InspectionPolicy ip2;
    ip2.user_policy_id = 7;
    ReloadSurvivorSubscriptions rss2(my_network_policy, ip2, survivor);

    unsigned factory_calls = 0;
    CountingHandler* h = nullptr;

    rss2.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
        [&]() -> DataHandler*
        {
            ++factory_calls;
            h = new CountingHandler();
            return h;
        });

    CHECK_EQUAL(1u, factory_calls);
    CHECK_TRUE(h != nullptr);
    CHECK_TRUE(h->live.load());
}

// on_bus_destroyed(nullptr) is well-defined and a no-op.
TEST(reload_survivor_subscriptions, on_bus_destroyed_null_is_noop)
{
    rss_on_bus_destroyed(nullptr);
}

// Factory may reenter RSS without deadlocking.  subscribe() must call
// the user-supplied factory OUTSIDE the registry lock so a factory
// whose constructor (or the factory body itself) calls back into
// rss.subscribe() / release() is safe.  Before the fix this test
// would deadlock on the non-recursive registry mutex.
TEST(reload_survivor_subscriptions, factory_can_reenter_subscribe_without_deadlock)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* inner = new CountingHandler();
    CountingHandler* outer = nullptr;

    rss.subscribe("outer", rss_pub_key, RssUtIds::EVENT,
        [&]() -> DataHandler*
        {
            // Reenter while the outer subscribe is in flight.  Must not
            // deadlock; the inner subscription must land.
            rss.subscribe("inner", rss_pub_key, RssUtIds::EVENT,
                [inner]() -> DataHandler* { return inner; });

            outer = new CountingHandler();
            return outer;
        });

    CHECK_TRUE(outer != nullptr);

    // Both subscriptions must be live and dispatch the published event.
    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, outer->calls);
    CHECK_EQUAL(1u, inner->calls);
}

// TSAN coverage for the reload-reconcile race: packet-thread release()
// may fire concurrently with the reconcile-thread subscribe() for the
// same survivor. Terminal state is nondeterministic (entry present iff
// subscribe won the last round); the size assertion is a sanity bound.
TEST(reload_survivor_subscriptions, concurrent_subscribe_and_release)
{
    FakeInspector survivor;
    constexpr unsigned ITERATIONS = 500;
    std::atomic<bool> start{false};

    std::thread releaser([&]()
    {
        while ( !start.load(std::memory_order_acquire) ) { }
        for ( unsigned i = 0; i < ITERATIONS; i++ )
        {
            rss_release(survivor);
            std::this_thread::yield();
        }
    });

    start.store(true, std::memory_order_release);

    for ( unsigned i = 0; i < ITERATIONS; i++ )
    {
        ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);
        rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        std::this_thread::yield();
    }

    releaser.join();

    auto v = rss_list_survivors();
    CHECK_TRUE(v.size() <= 1);
}

// TSAN proof that a packet thread cannot touch a survivor while
// reconcile_map() still holds it reconciling; see dev_notes.txt.
TEST(reload_survivor_subscriptions, release_orders_tterm_write_against_reconcile_no_data_race)
{
    RacingInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* h = new CountingHandler();
    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT, [h]() -> DataHandler* { return h; });

    auto snap = rss_list_survivors();
    CHECK_EQUAL(1u, snap.size());

    // Direct contract check: a packet thread attempting release() while
    // reconciling is held must be deferred, not allowed through.
    CHECK_FALSE(rss_release(survivor));
    CHECK_TRUE(h->live.load());

    std::atomic<bool> packet_done{false};

    std::thread packet_thread([&]()
    {
        while ( !rss_release(survivor) )
            std::this_thread::yield();

        survivor.state = 99;   // stands in for tterm()'s state mutation
        packet_done.store(true, std::memory_order_release);
    });

    for ( int i = 0; i < 10000; ++i )
        survivor.state = i;    // stands in for register_reload_survivor_handlers()

    rss_end_reconcile(survivor);
    packet_thread.join();

    CHECK_TRUE(packet_done.load(std::memory_order_acquire));
    CHECK_EQUAL(99, survivor.state);
    CHECK_FALSE(h->live.load());
    CHECK_EQUAL(0u, rss_list_survivors().size());
}

// subscribe() snapshots the (np, ip) user_policy_id pair on the first
// call so list_survivors() can return them across the destruction of
// the original ip.  Subsequent subscribe() calls do NOT overwrite the
// snapshot (it identifies the matching policy permanently for this
// survivor).
TEST(reload_survivor_subscriptions, subscribe_snapshots_ids_once)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
        []() -> DataHandler* { return new CountingHandler(); });

    auto v = rss_list_survivors();
    CHECK_EQUAL(1u, v.size());
    POINTERS_EQUAL(&survivor, v[0].survivor);
    CHECK_EQUAL(42u, v[0].np_user_id);
    CHECK_EQUAL(7u, v[0].ip_user_id);

    // Second subscribe under a different (np, ip) view of the same
    // survivor: ids must NOT be overwritten.  In production this would
    // happen on a subsequent reload's reconcile_map where a fresh RSS
    // is constructed against the new SC's policies.
    NetworkPolicy other_np;
    other_np.user_policy_id = 999;
    InspectionPolicy other_ip;
    other_ip.user_policy_id = 888;
    ReloadSurvivorSubscriptions rss2(other_np, other_ip, survivor);
    rss2.subscribe("k2", rss_pub_key, RssUtIds::EVENT,
        []() -> DataHandler* { return new CountingHandler(); });

    auto v2 = rss_list_survivors();
    CHECK_EQUAL(1u, v2.size());
    CHECK_EQUAL(42u, v2[0].np_user_id);
    CHECK_EQUAL(7u, v2[0].ip_user_id);
}

// list_survivors() returns one entry per surviving inspector, regardless
// of how many handlers each one has.  Handler-list cardinality is an
// internal detail; the iteration contract is one-row-per-survivor.
TEST(reload_survivor_subscriptions, list_survivors_one_row_per_inspector)
{
    FakeInspector survivor_a;
    FakeInspector survivor_b;

    {
        ReloadSurvivorSubscriptions rss_a(my_network_policy, my_inspection_policy, survivor_a);
        rss_a.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        rss_a.subscribe("k2", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }
    {
        ReloadSurvivorSubscriptions rss_b(my_network_policy, my_inspection_policy, survivor_b);
        rss_b.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }

    auto v = rss_list_survivors();
    CHECK_EQUAL(2u, v.size());
}

// End-to-end multi-reload simulation: subscribe on ip1, destroy ip1
// (mimicking SC1 -> SC2 reload), look up the survivor via
// list_survivors() against the snapshotted ids, re-subscribe on ip2
// (the new SC's matching policy), destroy ip2, repeat for ip3, then
// release().  This is the framework-level proof that the reattach
// chain works across an arbitrary number of reload generations.
TEST(reload_survivor_subscriptions, multi_reload_reattach_chain)
{
    FakeInspector survivor;

    // Initial subscribe on ip1 (SC1's matching ip).
    auto* ip1 = new InspectionPolicy();
    ip1->user_policy_id = 7;
    {
        ReloadSurvivorSubscriptions rss(my_network_policy, *ip1, survivor);
        rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }

    // SC1 dies.  Handler list stripped; entry retained.
    delete ip1;
    auto after_sc1 = rss_list_survivors();
    CHECK_EQUAL(1u, after_sc1.size());
    CHECK_EQUAL(7u, after_sc1[0].ip_user_id);
    rss_end_reconcile(survivor);

    // SC2 reload: reconcile_map iterates list_survivors and reattaches
    // to the new SC's matching ip (ip2).
    auto* ip2 = new InspectionPolicy();
    ip2->user_policy_id = 7;  // same user_policy_id -> matching
    {
        ReloadSurvivorSubscriptions rss(my_network_policy, *ip2, survivor);
        rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }

    // SC2 dies.  Handler list stripped; entry retained.
    delete ip2;
    auto after_sc2 = rss_list_survivors();
    CHECK_EQUAL(1u, after_sc2.size());
    CHECK_EQUAL(7u, after_sc2[0].ip_user_id);
    rss_end_reconcile(survivor);

    // SC3 reload: reattach again.
    auto* ip3 = new InspectionPolicy();
    ip3->user_policy_id = 7;
    {
        ReloadSurvivorSubscriptions rss(my_network_policy, *ip3, survivor);
        rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }

    // Flow finally drains: release() walks the live handlers (on ip3
    // here) and erases the entry.
    rss_release(survivor);

    auto after_release = rss_list_survivors();
    CHECK_EQUAL(0u, after_release.size());

    // Subsequent ~DataBus(ip3) must still be safe even though release
    // already retired the handlers.  No leak, no double-free.
    delete ip3;
}

//--------------------------------------------------------------------------
// serviceability peg tests
//--------------------------------------------------------------------------

// Single-reload scenario mirroring the finalised peg table:
//   install 3 handlers on SC1 -> reload strips SC1 -> reinstall 3 on SC2
//   -> release drains all 3.
TEST(reload_survivor_subscriptions, pegs_single_reload_scenario)
{
    FakeInspector s1;
    FakeInspector s2;
    FakeInspector s3;

    auto* ip1 = new InspectionPolicy();
    ip1->user_policy_id = 7;

    // Phase A: install 3 handlers on SC1's bus.
    {
        ReloadSurvivorSubscriptions r1(my_network_policy, *ip1, s1);
        r1.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        ReloadSurvivorSubscriptions r2(my_network_policy, *ip1, s2);
        r2.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        ReloadSurvivorSubscriptions r3(my_network_policy, *ip1, s3);
        r3.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }

    CHECK_EQUAL(3u, rss_stats.installed);
    CHECK_EQUAL(3u, rss_stats.active);
    CHECK_EQUAL(3u, rss_stats.registry_tracked);
    CHECK_EQUAL(0u, rss_stats.retired);
    CHECK_EQUAL(0u, rss_stats.stripped);
    CHECK_EQUAL(0u, rss_stats.bus_destroyed);

    // Phase B: SC1 dies -- ~DataBus strips 3 handler entries, entries retained.
    delete ip1;

    CHECK_EQUAL(1u, rss_stats.bus_destroyed);
    CHECK_EQUAL(3u, rss_stats.stripped);
    CHECK_EQUAL(0u, rss_stats.active);
    CHECK_EQUAL(3u, rss_stats.registry_tracked);  // entries retained

    // Phase C: SC2 reload -- reinstall the same 3 survivors on new ip.
    auto* ip2 = new InspectionPolicy();
    ip2->user_policy_id = 7;
    {
        ReloadSurvivorSubscriptions r1(my_network_policy, *ip2, s1);
        r1.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        ReloadSurvivorSubscriptions r2(my_network_policy, *ip2, s2);
        r2.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        ReloadSurvivorSubscriptions r3(my_network_policy, *ip2, s3);
        r3.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }

    CHECK_EQUAL(6u, rss_stats.installed);         // 3 + 3
    CHECK_EQUAL(3u, rss_stats.active);            // 3 stripped + 3 new
    CHECK_EQUAL(3u, rss_stats.registry_tracked);  // unchanged (same 3 keys)

    // Phase D: drain -- release each survivor.
    rss_release(s1);
    rss_release(s2);
    rss_release(s3);

    CHECK_EQUAL(3u, rss_stats.retired);
    CHECK_EQUAL(0u, rss_stats.active);
    CHECK_EQUAL(0u, rss_stats.registry_tracked);

    delete ip2;
    // second bus_destroyed but no more handlers to strip.
    CHECK_EQUAL(2u, rss_stats.bus_destroyed);
    CHECK_EQUAL(3u, rss_stats.stripped);
}

// Two-reload scenario mirroring the second finalised table example:
//   install 3 on SC1 -> strip SC1 -> reinstall 3 on SC2 -> strip SC2
//   -> reinstall 3 on SC3 -> drain.
TEST(reload_survivor_subscriptions, pegs_two_reload_scenario)
{
    FakeInspector s1;
    FakeInspector s2;
    FakeInspector s3;

    auto install_all = [&](InspectionPolicy& ip)
    {
        ReloadSurvivorSubscriptions r1(my_network_policy, ip, s1);
        r1.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        ReloadSurvivorSubscriptions r2(my_network_policy, ip, s2);
        r2.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
        ReloadSurvivorSubscriptions r3(my_network_policy, ip, s3);
        r3.subscribe("k", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    };

    auto* ip1 = new InspectionPolicy(); ip1->user_policy_id = 7;
    install_all(*ip1);
    delete ip1;  // SC1 strip

    auto* ip2 = new InspectionPolicy(); ip2->user_policy_id = 7;
    install_all(*ip2);
    delete ip2;  // SC2 strip

    auto* ip3 = new InspectionPolicy(); ip3->user_policy_id = 7;
    install_all(*ip3);

    // Cumulative expectations after 3 install phases and 2 bus destroys:
    //   installed:  9 (3 per phase)
    //   stripped:   6 (3 per SC1 strip + 3 per SC2 strip)
    //   active:     3 (SC3's live handlers)
    //   registry_tracked: 3 (three distinct survivors, never released)
    //   bus_destroyed: 2 (SC1, SC2)
    CHECK_EQUAL(9u, rss_stats.installed);
    CHECK_EQUAL(6u, rss_stats.stripped);
    CHECK_EQUAL(3u, rss_stats.active);
    CHECK_EQUAL(3u, rss_stats.registry_tracked);
    CHECK_EQUAL(2u, rss_stats.bus_destroyed);
    CHECK_EQUAL(0u, rss_stats.retired);

    rss_release(s1);
    rss_release(s2);
    rss_release(s3);

    CHECK_EQUAL(3u, rss_stats.retired);
    CHECK_EQUAL(0u, rss_stats.active);
    CHECK_EQUAL(0u, rss_stats.registry_tracked);

    delete ip3;
}

// Many-reload-cycle leak check for one long-lived survivor, standing in
// for a sustained-traffic run where pcap/decrypt timing can't be trusted
// (see dev_notes.txt on rss_bus_destroyed/rss_policy_resolve_fail). The
// gauges must never grow past one tracked entry mid-run, and must return
// to zero once the survivor's traffic finally quiesces.
TEST(reload_survivor_subscriptions, many_reload_cycles_single_survivor_returns_to_baseline)
{
    FakeInspector survivor;
    constexpr unsigned CYCLE_COUNT = 5000;
    InspectionPolicy* prev_ip = nullptr;

    for ( unsigned i = 0; i < CYCLE_COUNT; i++ )
    {
        // Mirrors reconcile_map()'s list_survivors() sweep on every reload;
        // every entry returned needs exactly one end_reconcile() call. The
        // very first sweep predates any subscribe(), so it returns nothing.
        auto snap = rss_list_survivors();
        CHECK_EQUAL(i == 0 ? 0u : 1u, snap.size());
        rss_end_reconcile(survivor);

        auto* ip = new InspectionPolicy();
        ip->user_policy_id = 7;

        {
            ReloadSurvivorSubscriptions rss(my_network_policy, *ip, survivor);
            rss.subscribe("k", rss_pub_key, RssUtIds::EVENT,
                []() -> DataHandler* { return new CountingHandler(); });
        }

        CHECK_EQUAL(1u, rss_stats.registry_tracked);  // never more than one tracked entry

        delete prev_ip;  // previous cycle's bus torn down only after the new one is live
        prev_ip = ip;

        CHECK_EQUAL(1u, rss_stats.active);  // exactly this cycle's handler
    }

    CHECK_EQUAL(CYCLE_COUNT, rss_stats.installed);
    CHECK_EQUAL(CYCLE_COUNT - 1, rss_stats.list_returned);  // every sweep but the first
    CHECK_EQUAL(CYCLE_COUNT - 1, rss_stats.bus_destroyed);
    CHECK_EQUAL(CYCLE_COUNT - 1, rss_stats.stripped);
    CHECK_EQUAL(0u, rss_stats.dedup_conflicts);

    rss_release(survivor);  // the flow finally drains

    CHECK_EQUAL(1u, rss_stats.retired);
    CHECK_EQUAL(0u, rss_stats.active);
    CHECK_EQUAL(0u, rss_stats.registry_tracked);  // the leak check

    delete prev_ip;  // last bus torn down after release -- must be a harmless no-op strip
    CHECK_EQUAL(CYCLE_COUNT, rss_stats.bus_destroyed);
    CHECK_EQUAL(CYCLE_COUNT - 1, rss_stats.stripped);  // nothing left to strip this time

    // Downstream publish contract: a handler still on a live bus after
    // release() must be skipped, not delivered. DataBus::publish() (see
    // data_bus.cc) always targets my_inspection_policy's bus in this test
    // fixture, so exercise that bus specifically for this check.
    {
        ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);
        rss.subscribe("k2", rss_pub_key, RssUtIds::EVENT,
            []() -> DataHandler* { return new CountingHandler(); });
    }
    rss_release(survivor);

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, rss_stats.dead_handler_skips);
}

// Same validation, shaped like the SIT's actual traffic pattern: many
// distinct survivors across many reload cycles, released at different
// times rather than all at once. The only assertion that has to hold is
// the one the SIT itself relied on -- once every session finishes,
// nothing is left tracked.
TEST(reload_survivor_subscriptions, high_volume_overlapping_survivors_drain_to_zero)
{
    constexpr unsigned TOTAL_SURVIVORS = 500;
    constexpr unsigned CYCLES_PER_SURVIVOR = 10;

    std::vector<FakeInspector*> survivors;
    std::vector<InspectionPolicy*> live_ip(TOTAL_SURVIVORS, nullptr);
    for ( unsigned s = 0; s < TOTAL_SURVIVORS; s++ )
        survivors.push_back(new FakeInspector());

    unsigned released_mid_run = 0;

    for ( unsigned s = 0; s < TOTAL_SURVIVORS; s++ )
    {
        for ( unsigned c = 0; c < CYCLES_PER_SURVIVOR; c++ )
        {
            auto* ip = new InspectionPolicy();
            ip->user_policy_id = 7;
            {
                ReloadSurvivorSubscriptions rss(my_network_policy, *ip, *survivors[s]);
                rss.subscribe("k", rss_pub_key, RssUtIds::EVENT,
                    []() -> DataHandler* { return new CountingHandler(); });
            }
            delete live_ip[s];  // previous cycle's bus, now superseded
            live_ip[s] = ip;
        }

        // Every third session finishes early, mid-run, rather than all
        // sessions completing together at the end.
        if ( s % 3 == 0 )
        {
            rss_release(*survivors[s]);
            released_mid_run++;
        }
    }

    CHECK_EQUAL(TOTAL_SURVIVORS * CYCLES_PER_SURVIVOR, rss_stats.installed);
    CHECK_EQUAL(0u, rss_stats.dedup_conflicts);
    CHECK_EQUAL(released_mid_run, rss_stats.retired);
    CHECK_EQUAL(TOTAL_SURVIVORS - released_mid_run, rss_stats.registry_tracked);

    for ( unsigned s = 0; s < TOTAL_SURVIVORS; s++ )
    {
        if ( s % 3 != 0 )
            rss_release(*survivors[s]);
    }

    CHECK_EQUAL(TOTAL_SURVIVORS, rss_stats.retired);
    CHECK_EQUAL(0u, rss_stats.active);
    CHECK_EQUAL(0u, rss_stats.registry_tracked);  // all sessions done -> nothing left

    for ( auto* ip : live_ip )
        delete ip;  // eventual bus teardown after release; must be a harmless no-op strip

    for ( auto* s : survivors )
        delete s;
}

// _publish() bumps rss_stats.dead_handler_skips when a handler's live
// flag has been cleared by release().  This is the single peg that
// catches the CSCwu55928 class of bug -- a survivor released while a
// downstream still holds a live subscription pointer.
TEST(reload_survivor_subscriptions, pegs_dead_handler_publish_skip)
{
    FakeInspector survivor;
    ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, survivor);

    CountingHandler* h = new CountingHandler();
    rss.subscribe("k", rss_pub_key, RssUtIds::EVENT,
        [h]() -> DataHandler* { return h; });

    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, h->calls);
    CHECK_EQUAL(0u, rss_stats.dead_handler_skips);

    rss_release(survivor);

    // Handler is still on the bus but live == false.  Publish must
    // skip the dispatch AND bump the peg.
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, h->calls);
    CHECK_EQUAL(1u, rss_stats.dead_handler_skips);

    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(2u, rss_stats.dead_handler_skips);
}

// list_survivors() accumulates into rss_stats.list_returned.
TEST(reload_survivor_subscriptions, pegs_list_survivors_returned)
{
    FakeInspector s1;
    FakeInspector s2;

    ReloadSurvivorSubscriptions r1(my_network_policy, my_inspection_policy, s1);
    r1.subscribe("k", rss_pub_key, RssUtIds::EVENT,
        []() -> DataHandler* { return new CountingHandler(); });
    ReloadSurvivorSubscriptions r2(my_network_policy, my_inspection_policy, s2);
    r2.subscribe("k", rss_pub_key, RssUtIds::EVENT,
        []() -> DataHandler* { return new CountingHandler(); });

    (void)rss_list_survivors();  // +2
    (void)rss_list_survivors();  // +2

    CHECK_EQUAL(4u, rss_stats.list_returned);
}

// Value-mapping test: a distinct value per field catches two pegs wired
// to each other's index while the total count still matches RssPeg::Count
// (which the static_assert on rss_pegs[] cannot detect on its own).
TEST(reload_survivor_subscriptions, prep_counts_mapping_matches_named_indices)
{
    RssStats stats;
    stats.installed.store(101, std::memory_order_relaxed);
    stats.retired.store(102, std::memory_order_relaxed);
    stats.bus_destroyed.store(103, std::memory_order_relaxed);
    stats.policy_resolution_failures.store(104, std::memory_order_relaxed);
    stats.list_returned.store(105, std::memory_order_relaxed);
    stats.stripped.store(106, std::memory_order_relaxed);
    stats.dead_handler_skips.store(107, std::memory_order_relaxed);
    stats.active.store(108, std::memory_order_relaxed);
    stats.registry_tracked.store(109, std::memory_order_relaxed);
    stats.dedup_conflicts.store(110, std::memory_order_relaxed);

    PegCount out[static_cast<size_t>(RssPeg::Count)] = {};
    rss_stats_to_pegcounts(stats, out);

    CHECK_EQUAL(101u, out[static_cast<size_t>(RssPeg::Installed)]);
    CHECK_EQUAL(102u, out[static_cast<size_t>(RssPeg::Retired)]);
    CHECK_EQUAL(103u, out[static_cast<size_t>(RssPeg::BusDestroyed)]);
    CHECK_EQUAL(104u, out[static_cast<size_t>(RssPeg::PolicyResolutionFailures)]);
    CHECK_EQUAL(105u, out[static_cast<size_t>(RssPeg::ListReturned)]);
    CHECK_EQUAL(106u, out[static_cast<size_t>(RssPeg::Stripped)]);
    CHECK_EQUAL(107u, out[static_cast<size_t>(RssPeg::DeadHandlerSkips)]);
    CHECK_EQUAL(108u, out[static_cast<size_t>(RssPeg::Active)]);
    CHECK_EQUAL(109u, out[static_cast<size_t>(RssPeg::RegistryTracked)]);
    CHECK_EQUAL(110u, out[static_cast<size_t>(RssPeg::DedupConflicts)]);
}

// reset() must not zero the NOW-type active/registry_tracked gauges while
// survivors are still live: a later release() decrements from whatever
// count is actually there, so zeroing them independent of the registry
// would underflow the atomics on the next release() (wraps to near
// UINT64_MAX). installed/retired (SUM types) are still expected to reset.
TEST(reload_survivor_subscriptions, pegs_reset_does_not_underflow_now_gauges)
{
    FakeInspector s1;
    FakeInspector s2;

    ReloadSurvivorSubscriptions r1(my_network_policy, my_inspection_policy, s1);
    r1.subscribe("k", rss_pub_key, RssUtIds::EVENT,
        []() -> DataHandler* { return new CountingHandler(); });
    ReloadSurvivorSubscriptions r2(my_network_policy, my_inspection_policy, s2);
    r2.subscribe("k", rss_pub_key, RssUtIds::EVENT,
        []() -> DataHandler* { return new CountingHandler(); });

    CHECK_EQUAL(2u, rss_stats.active);
    CHECK_EQUAL(2u, rss_stats.registry_tracked);

    // Simulate a stats-reset request landing while both survivors are
    // still live in the registry.
    rss_stats.reset();

    // SUM counters reset; NOW gauges must still reflect the live registry.
    CHECK_EQUAL(0u, rss_stats.installed);
    CHECK_EQUAL(2u, rss_stats.active);
    CHECK_EQUAL(2u, rss_stats.registry_tracked);

    // Draining both survivors after the reset must land exactly at zero,
    // not underflow past it.
    rss_release(s1);
    CHECK_EQUAL(1u, rss_stats.active);
    CHECK_EQUAL(1u, rss_stats.registry_tracked);

    rss_release(s2);
    CHECK_EQUAL(0u, rss_stats.active);
    CHECK_EQUAL(0u, rss_stats.registry_tracked);
}

//-------------------------------------------------------------------------
// zero flow refs: subscribed survivor deleted with no pending flow ref
//-------------------------------------------------------------------------
// A removed inspector with ZERO flow refs never runs finish_pending_tterm,
// so its only release() call comes from ~Inspector() itself, via
// ~PIG -> dump_handler -> is_inactive() -> dtor. Proves that path alone
// retires the registry entry and handler before any later publish.

namespace
{

class TrackingInspector : public Inspector
{
public:
    TrackingInspector() : Inspector() { }
    void notify() { ++notifications; }
    unsigned notifications = 0;
};

class RoutingHandler : public DataHandler
{
public:
    RoutingHandler(TrackingInspector* s) : DataHandler("rss_zero_ref"), survivor(s) { }

    void handle(DataEvent&, Flow*) override
    { survivor->notify(); }

private:
    TrackingInspector* survivor;
};

// same shape as RoutingHandler, but sleeps before touching survivor
class SlowRoutingHandler : public DataHandler
{
public:
    SlowRoutingHandler(TrackingInspector* s, std::atomic<bool>& entered_) :
        DataHandler("rss_zero_ref_slow"), survivor(s), entered(entered_) { }

    void handle(DataEvent&, Flow*) override
    {
        entered.store(true, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        survivor->notify();
    }

private:
    TrackingInspector* survivor;
    std::atomic<bool>& entered;
};

} // namespace

TEST(reload_survivor_subscriptions, subscribed_survivor_deleted_with_zero_flow_refs)
{
    auto* survivor = new TrackingInspector();
    auto* handler = new RoutingHandler(survivor);

    {
        ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, *survivor);
        rss.subscribe("zero_ref_key", rss_pub_key, RssUtIds::EVENT,
            [handler]() -> DataHandler* { return handler; });
    }

    // sanity: handler dispatches while survivor is alive
    CountingEvent e;
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
    CHECK_EQUAL(1u, survivor->notifications);

    // dump_handler(X) fires api->dtor(X) here with no pending flow ref;
    // ~Inspector() calls release(*this) directly
    delete survivor;

    // registry entry is retired -- no dangling survivor left behind
    auto v = rss_list_survivors();
    CHECK_EQUAL(0u, v.size());

    // ASAN gate: would UAF here if release() had left the handler live
    DataBus::publish(pub_id, RssUtIds::EVENT, e);
}

// concurrent counterpart to subscribed_survivor_deleted_with_zero_flow_refs:
// ASAN gate for a delete racing an in-flight handle() on another thread.
TEST(reload_survivor_subscriptions, subscribed_survivor_delete_races_inflight_handle)
{
    auto* survivor = new TrackingInspector();
    std::atomic<bool> entered{false};
    auto* handler = new SlowRoutingHandler(survivor, entered);

    {
        ReloadSurvivorSubscriptions rss(my_network_policy, my_inspection_policy, *survivor);
        rss.subscribe("zero_ref_key_slow", rss_pub_key, RssUtIds::EVENT,
            [handler]() -> DataHandler* { return handler; });
    }

    CountingEvent e;
    std::thread publisher([&]()
    { DataBus::publish(pub_id, RssUtIds::EVENT, e); });

    while ( !entered.load(std::memory_order_acquire) )
        std::this_thread::yield();

    delete survivor;

    publisher.join();
}

// await_quiescent()/release() copy a raw
// RssLeaseHandler* out of the registry lock into to_drain, then drain()
// dereferences it after unlocking. That pointer's real owner is the
// DataBus it's subscribed to, not the survivor -- a failed reload
// re-subscribes every tracked survivor onto its tentative (not yet
// verified) bus in reconcile_map(), and if verification then fails,
// ~SnortConfig tears that bus down while a packet thread may already be
// mid-drain on the same lease. ASAN gate for that bus teardown racing an
// in-flight await_quiescent() drain -- would UAF in ~RssLeaseHandler
// without the borrow-count fix.
TEST(reload_survivor_subscriptions, await_quiescent_races_tentative_bus_teardown)
{
    FakeInspector survivor;

    // Heap-allocate ip to stand in for a reload's tentative InspectionPolicy,
    // torn down mid-test the way a failed reload's cleanup would.
    auto* ip = new InspectionPolicy();
    ip->user_policy_id = 7;

    std::atomic<bool> entered{false};
    std::atomic<bool> done{false};
    auto* handler = new SlowHandler(entered, done, 100);
    unsigned local_pub_id;

    {
        ReloadSurvivorSubscriptions rss(my_network_policy, *ip, survivor);
        rss.subscribe("k1", rss_pub_key, RssUtIds::EVENT,
            [handler]() -> DataHandler* { return handler; });
        local_pub_id = DataBus::get_id(rss_pub_key);
    }

    // DataBus::publish() routes through get_inspection_policy(), which the
    // mock reads from this data object -- point it at ip so the publish
    // lands on ip->dbus, the bus we're about to tear down.
    mock().setDataObject("my_inspection_policy", "InspectionPolicy", ip);

    CountingEvent e;
    std::thread publisher([&]()
    { DataBus::publish(local_pub_id, RssUtIds::EVENT, e); });

    while ( !entered.load(std::memory_order_acquire) )
        std::this_thread::yield();

    // Copies the lease into to_drain and starts spinning in drain() while
    // handle() is still mid-sleep (inflight == 1).
    std::thread waiter([&]()
    { rss_await_quiescent(survivor); });

    // Give await_quiescent() time to finish its locked copy/borrow before
    // tearing the bus down underneath it.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Simulates a failed reload's ~SnortConfig destroying the tentative
    // bus while waiter's drain() is still reading this lease's inflight
    // counter.
    delete ip;

    publisher.join();
    waiter.join();
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // event_map is not released until after cpputest gives up
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
